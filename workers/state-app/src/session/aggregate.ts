import {
  ProtocolValidationError,
  digestStructuredValue,
  encodeCanonicalCbor,
  normalizeProtocolValue,
  parseAgentCheckpoint,
  parseDigest,
  parseDispatchPermitClaims,
  parseEffectClaim,
  parseEngineStepResult,
  validateAgentCheckpoint,
  type AgentCheckpoint,
  type Digest,
  type EffectIntent,
  type EngineKind,
  type NormalizedValue,
} from "@circulusd/protocol-types";

import { sessionError } from "./errors.ts";
import {
  SESSION_CHECKPOINT_DIGEST_DOMAIN,
  SESSION_CHECKPOINT_DIGEST_SCHEMA_VERSION,
  SESSION_COMMAND_MAX_ENCODED_BYTES,
  SESSION_COMMAND_SCHEMA_VERSION,
  SESSION_EFFECT_REQUEST_DIGEST_DOMAIN,
  SESSION_EFFECT_REQUEST_DIGEST_SCHEMA_VERSION,
  SESSION_PUBLIC_EVENT_REPLAY_MAX_EVENTS,
  SESSION_STATE_SCHEMA_VERSION,
  SESSION_STATE_MAX_ENCODED_BYTES,
  SESSION_TURN_INPUT_DIGEST_DOMAIN,
  SESSION_TURN_INPUT_DIGEST_SCHEMA_VERSION,
  SESSION_VALUE_MAX_ENCODED_BYTES,
  type ApplySessionCommandResult,
  type CreateSessionStateInput,
  type EffectSettlement,
  type SessionAggregateState,
  type SessionCommand,
  type SessionCommandOutcome,
  type SessionEffect,
  type SessionPublicEventReplay,
  type TurnAdmissionReceipt,
} from "./types.ts";
import type { SessionAggregateErrorCode } from "./errors.ts";

const textEncoder = new TextEncoder();

const LEGACY_SESSION_STATE_FIELDS = [
  "schemaVersion",
  "sessionId",
  "tenantId",
  "userId",
  "workspaceId",
  "runtimeRevisionDigest",
  "runtimePointer",
  "policySnapshotDigest",
  "emergencyOverlayDigest",
  "engineKind",
  "adapterAbiVersion",
  "checkpointSchemaVersion",
  "status",
  "eventSequence",
  "nextTurnSequence",
  "activeTurn",
  "queuedTurns",
  "terminalTurns",
  "knownTurnIds",
  "latestSettledTurn",
  "effects",
  "placementGeneration",
  "sandboxGeneration",
  "authorizationGeneration",
  "commandReceipts",
] as const;

const SESSION_STATE_FIELDS = [
  ...LEGACY_SESSION_STATE_FIELDS,
  "publicEventSequence",
  "publicEvents",
  "turnAdmissionReceipts",
] as const;

function validatedExactFields(
  value: unknown,
  requiredFields: readonly string[],
  optionalFields: readonly string[],
  field: string,
  errorCode: SessionAggregateErrorCode,
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    sessionError(errorCode, `${field} must be a plain object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    sessionError(errorCode, `${field} must be a plain object`);
  }
  const record = value as Record<string, unknown>;
  for (const key of Reflect.ownKeys(record)) {
    if (
      typeof key !== "string" ||
      (!requiredFields.includes(key) && !optionalFields.includes(key))
    ) {
      sessionError(errorCode, `${field} has unknown field ${String(key)}`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (
      descriptor === undefined ||
      !descriptor.enumerable ||
      !("value" in descriptor)
    ) {
      sessionError(errorCode, `${field}.${key} must be an enumerable data property`);
    }
  }
  for (const requiredField of requiredFields) {
    if (!Object.prototype.hasOwnProperty.call(record, requiredField)) {
      sessionError(errorCode, `${field} is missing field ${requiredField}`);
    }
  }
  return record;
}

function validatedNormalizedValue(
  value: unknown,
  field: string,
  maxBytes: number,
  requireCanonical: boolean,
  errorCode: SessionAggregateErrorCode,
): NormalizedValue {
  try {
    const normalized = normalizeProtocolValue(value);
    if (requireCanonical) {
      const pending: unknown[] = [value];
      while (pending.length > 0) {
        const current = pending.pop();
        if (typeof current === "string") {
          if (current !== current.normalize("NFC")) {
            sessionError(errorCode, `${field} must contain only NFC-normalized strings`);
          }
          continue;
        }
        if (
          current === null ||
          typeof current !== "object" ||
          current instanceof Uint8Array
        ) {
          continue;
        }
        if (Array.isArray(current)) {
          pending.push(...current);
          continue;
        }
        for (const key of Object.keys(current)) {
          if (key !== key.normalize("NFC")) {
            sessionError(errorCode, `${field} must contain only NFC-normalized field names`);
          }
          pending.push((current as Record<string, unknown>)[key]);
        }
      }
    }
    encodeCanonicalCbor(normalized, { maxBytes });
    return normalized;
  } catch (error) {
    if (error instanceof ProtocolValidationError) {
      sessionError(errorCode, `${field} is not a bounded protocol value: ${error.message}`);
    }
    throw error;
  }
}

function validatedIdentifier(value: unknown, field: string): string {
  let normalized;
  try {
    normalized = normalizeProtocolValue(value);
  } catch (error) {
    if (error instanceof ProtocolValidationError) {
      sessionError("INVALID_ARGUMENT", `${field}: ${error.message}`);
    }
    throw error;
  }
  if (typeof normalized !== "string" || normalized.length === 0) {
    sessionError("INVALID_ARGUMENT", `${field} must be a non-empty string`);
  }
  if (normalized !== value) {
    sessionError("INVALID_ARGUMENT", `${field} must be NFC-normalized`);
  }
  if (textEncoder.encode(normalized).byteLength > 256 || /\p{Cc}/u.test(normalized)) {
    sessionError("INVALID_ARGUMENT", `${field} is not a valid protocol identifier`);
  }
  return normalized;
}

function validatedInteger(value: unknown, field: string, minimum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) {
    sessionError(
      "INVALID_ARGUMENT",
      `${field} must be a safe integer greater than or equal to ${minimum}`,
    );
  }
  return value;
}

function validatedEngineKind(value: unknown, field: string): EngineKind {
  if (value !== "low-level" && value !== "agent-harness") {
    sessionError("INVALID_ARGUMENT", `${field} must be low-level or agent-harness`);
  }
  return value;
}

function checkpointMatchesSession(
  state: SessionAggregateState,
  checkpoint: AgentCheckpoint,
  turnId: string,
  requireActiveRuntime = true,
): void {
  if (checkpoint.sessionId !== state.sessionId) {
    sessionError("FAILED_PRECONDITION", "checkpoint sessionId does not match the session");
  }
  if (checkpoint.turnId !== turnId) {
    sessionError("FAILED_PRECONDITION", "checkpoint turnId does not match the active turn");
  }
  if (
    requireActiveRuntime &&
    checkpoint.runtimeRevisionDigest !== state.runtimeRevisionDigest
  ) {
    sessionError(
      "FAILED_PRECONDITION",
      "checkpoint runtimeRevisionDigest does not match the active runtime",
    );
  }
  if (checkpoint.engineKind !== state.engineKind) {
    sessionError("FAILED_PRECONDITION", "checkpoint engineKind does not match the session");
  }
  if (checkpoint.adapterAbiVersion !== state.adapterAbiVersion) {
    sessionError(
      "FAILED_PRECONDITION",
      "checkpoint adapterAbiVersion does not match the active adapter",
    );
  }
  if (checkpoint.checkpointSchemaVersion !== state.checkpointSchemaVersion) {
    sessionError(
      "FAILED_PRECONDITION",
      "checkpointSchemaVersion does not match the active adapter schema",
    );
  }
}

function effectById(state: SessionAggregateState, effectId: string): SessionEffect | undefined {
  return state.effects.find((effect) => effect.effectId === effectId);
}

function assertEffectSettlement(
  value: unknown,
  field: string,
  errorCode: SessionAggregateErrorCode,
): void {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    sessionError(errorCode, `${field} must be a plain object`);
  }
  const kind = (value as { readonly kind?: unknown }).kind;
  switch (kind) {
    case "success": {
      const settlement = validatedExactFields(
        value,
        ["kind", "result"],
        [],
        field,
        errorCode,
      );
      validatedNormalizedValue(
        settlement.result,
        `${field}.result`,
        SESSION_VALUE_MAX_ENCODED_BYTES,
        true,
        errorCode,
      );
      break;
    }
    case "error": {
      const settlement = validatedExactFields(
        value,
        ["kind", "code", "message", "retryable"],
        [],
        field,
        errorCode,
      );
      validatedIdentifier(settlement.code, `${field}.code`);
      validatedIdentifier(settlement.message, `${field}.message`);
      if (typeof settlement.retryable !== "boolean") {
        sessionError(errorCode, `${field}.retryable must be a boolean`);
      }
      break;
    }
    case "interrupted_unknown":
    case "abandoned": {
      const settlement = validatedExactFields(
        value,
        ["kind", "reason"],
        [],
        field,
        errorCode,
      );
      validatedIdentifier(settlement.reason, `${field}.reason`);
      break;
    }
    default:
      sessionError(errorCode, `${field} has an unknown settlement kind`);
  }
}

function assertSessionCommandOutcome(
  value: unknown,
  field: string,
  errorCode: SessionAggregateErrorCode,
): void {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    sessionError(errorCode, `${field} must be a plain object`);
  }
  const kind = (value as { readonly kind?: unknown }).kind;
  switch (kind) {
    case "turn_enqueued": {
      const outcome = validatedExactFields(
        value,
        ["kind", "turnId", "turnSequence", "activated"],
        [],
        field,
        errorCode,
      );
      validatedIdentifier(outcome.turnId, `${field}.turnId`);
      validatedInteger(outcome.turnSequence, `${field}.turnSequence`, 0);
      if (typeof outcome.activated !== "boolean") {
        sessionError(errorCode, `${field}.activated must be a boolean`);
      }
      break;
    }
    case "engine_step_committed": {
      const outcome = validatedExactFields(
        value,
        [
          "kind",
          "turnId",
          "boundaryKind",
          "checkpointSequence",
          "consumedEffectId",
          "preparedEffectId",
          "status",
        ],
        [],
        field,
        errorCode,
      );
      validatedIdentifier(outcome.turnId, `${field}.turnId`);
      validatedInteger(outcome.checkpointSequence, `${field}.checkpointSequence`, 1);
      if (
        outcome.boundaryKind !== "checkpoint" &&
        outcome.boundaryKind !== "effect_request" &&
        outcome.boundaryKind !== "turn_complete" &&
        outcome.boundaryKind !== "turn_error"
      ) {
        sessionError(errorCode, `${field}.boundaryKind is unknown`);
      }
      const expectedStatus =
        outcome.boundaryKind === "turn_complete"
          ? "completed"
          : outcome.boundaryKind === "turn_error"
            ? "failed"
            : "active";
      if (outcome.status !== expectedStatus) {
        sessionError(errorCode, `${field}.status disagrees with boundaryKind`);
      }
      if (outcome.consumedEffectId !== null) {
        validatedIdentifier(outcome.consumedEffectId, `${field}.consumedEffectId`);
      }
      if (outcome.preparedEffectId !== null) {
        validatedIdentifier(outcome.preparedEffectId, `${field}.preparedEffectId`);
      }
      if (
        (outcome.boundaryKind === "effect_request") !==
        (outcome.preparedEffectId !== null)
      ) {
        sessionError(errorCode, `${field}.preparedEffectId disagrees with boundaryKind`);
      }
      break;
    }
    case "effect_dispatched": {
      const outcome = validatedExactFields(
        value,
        ["kind", "effectId", "dispatchPermitClaims"],
        [],
        field,
        errorCode,
      );
      const effectId = validatedIdentifier(outcome.effectId, `${field}.effectId`);
      const claims = parseDispatchPermitClaims(outcome.dispatchPermitClaims);
      if (claims.effectId !== effectId) {
        sessionError(errorCode, `${field}.dispatchPermitClaims names another effect`);
      }
      break;
    }
    case "external_commit_recorded": {
      const outcome = validatedExactFields(
        value,
        ["kind", "effectId", "externalCommitId"],
        [],
        field,
        errorCode,
      );
      validatedIdentifier(outcome.effectId, `${field}.effectId`);
      validatedIdentifier(outcome.externalCommitId, `${field}.externalCommitId`);
      break;
    }
    case "effect_settled": {
      const outcome = validatedExactFields(
        value,
        ["kind", "effectId", "settlement"],
        [],
        field,
        errorCode,
      );
      validatedIdentifier(outcome.effectId, `${field}.effectId`);
      assertEffectSettlement(outcome.settlement, `${field}.settlement`, errorCode);
      break;
    }
    case "effect_recovered": {
      const outcome = validatedExactFields(
        value,
        ["kind", "effectId", "action"],
        ["dispatchPermitClaims"],
        field,
        errorCode,
      );
      const effectId = validatedIdentifier(outcome.effectId, `${field}.effectId`);
      if (
        outcome.action !== "retry" &&
        outcome.action !== "interrupted" &&
        outcome.action !== "blocked"
      ) {
        sessionError(errorCode, `${field}.action is unknown`);
      }
      const hasClaims = Object.prototype.hasOwnProperty.call(
        outcome,
        "dispatchPermitClaims",
      );
      if ((outcome.action === "retry") !== hasClaims) {
        sessionError(errorCode, `${field}.dispatchPermitClaims disagrees with action`);
      }
      if (hasClaims) {
        const claims = parseDispatchPermitClaims(outcome.dispatchPermitClaims);
        if (claims.effectId !== effectId) {
          sessionError(errorCode, `${field}.dispatchPermitClaims names another effect`);
        }
      }
      break;
    }
    case "confirmation_resolved": {
      const outcome = validatedExactFields(
        value,
        ["kind", "effectId", "decision"],
        ["dispatchPermitClaims"],
        field,
        errorCode,
      );
      const effectId = validatedIdentifier(outcome.effectId, `${field}.effectId`);
      if (outcome.decision !== "retry" && outcome.decision !== "abandon") {
        sessionError(errorCode, `${field}.decision is unknown`);
      }
      const hasClaims = Object.prototype.hasOwnProperty.call(
        outcome,
        "dispatchPermitClaims",
      );
      if ((outcome.decision === "retry") !== hasClaims) {
        sessionError(errorCode, `${field}.dispatchPermitClaims disagrees with decision`);
      }
      if (hasClaims) {
        const claims = parseDispatchPermitClaims(outcome.dispatchPermitClaims);
        if (claims.effectId !== effectId) {
          sessionError(errorCode, `${field}.dispatchPermitClaims names another effect`);
        }
      }
      break;
    }
    case "abort_requested": {
      const outcome = validatedExactFields(
        value,
        ["kind", "turnId", "status"],
        [],
        field,
        errorCode,
      );
      validatedIdentifier(outcome.turnId, `${field}.turnId`);
      if (
        outcome.status !== "active" &&
        outcome.status !== "needs_confirmation" &&
        outcome.status !== "aborted"
      ) {
        sessionError(errorCode, `${field}.status is unknown`);
      }
      break;
    }
    case "abort_finalized": {
      const outcome = validatedExactFields(
        value,
        ["kind", "turnId", "status"],
        [],
        field,
        errorCode,
      );
      validatedIdentifier(outcome.turnId, `${field}.turnId`);
      if (outcome.status !== "aborted") {
        sessionError(errorCode, `${field}.status must be aborted`);
      }
      break;
    }
    case "turn_lease_rotated": {
      const outcome = validatedExactFields(
        value,
        ["kind", "turnId", "turnLeaseGeneration", "leaseExpiresAt"],
        [],
        field,
        errorCode,
      );
      validatedIdentifier(outcome.turnId, `${field}.turnId`);
      validatedInteger(outcome.turnLeaseGeneration, `${field}.turnLeaseGeneration`, 1);
      validatedInteger(outcome.leaseExpiresAt, `${field}.leaseExpiresAt`, 1);
      break;
    }
    case "generations_rotated": {
      const outcome = validatedExactFields(
        value,
        [
          "kind",
          "placementGeneration",
          "sandboxGeneration",
          "authorizationGeneration",
          "emergencyOverlayDigest",
        ],
        [],
        field,
        errorCode,
      );
      validatedInteger(outcome.placementGeneration, `${field}.placementGeneration`, 0);
      validatedInteger(outcome.sandboxGeneration, `${field}.sandboxGeneration`, 0);
      validatedInteger(
        outcome.authorizationGeneration,
        `${field}.authorizationGeneration`,
        0,
      );
      parseDigest(outcome.emergencyOverlayDigest, `${field}.emergencyOverlayDigest`);
      break;
    }
    case "runtime_revision_staged": {
      const outcome = validatedExactFields(
        value,
        ["kind", "activeRevision", "candidateRevision", "switchGeneration"],
        [],
        field,
        errorCode,
      );
      const activeRevision = parseDigest(
        outcome.activeRevision,
        `${field}.activeRevision`,
      );
      const candidateRevision = parseDigest(
        outcome.candidateRevision,
        `${field}.candidateRevision`,
      );
      if (candidateRevision === activeRevision) {
        sessionError(errorCode, `${field} aliases active and candidate revisions`);
      }
      validatedInteger(outcome.switchGeneration, `${field}.switchGeneration`, 1);
      break;
    }
    case "runtime_candidate_discarded": {
      const outcome = validatedExactFields(
        value,
        [
          "kind",
          "activeRevision",
          "candidateRevision",
          "switchGeneration",
          "failureReceiptDigest",
        ],
        [],
        field,
        errorCode,
      );
      const activeRevision = parseDigest(
        outcome.activeRevision,
        `${field}.activeRevision`,
      );
      const candidateRevision = parseDigest(
        outcome.candidateRevision,
        `${field}.candidateRevision`,
      );
      if (candidateRevision === activeRevision) {
        sessionError(errorCode, `${field} aliases active and candidate revisions`);
      }
      validatedInteger(outcome.switchGeneration, `${field}.switchGeneration`, 1);
      parseDigest(outcome.failureReceiptDigest, `${field}.failureReceiptDigest`);
      break;
    }
    case "runtime_revision_activated": {
      const outcome = validatedExactFields(
        value,
        [
          "kind",
          "activeRevision",
          "previousRevision",
          "switchGeneration",
          "healthReceiptDigest",
          "migrationReceiptDigest",
        ],
        [],
        field,
        errorCode,
      );
      const activeRevision = parseDigest(
        outcome.activeRevision,
        `${field}.activeRevision`,
      );
      const previousRevision = parseDigest(
        outcome.previousRevision,
        `${field}.previousRevision`,
      );
      if (previousRevision === activeRevision) {
        sessionError(errorCode, `${field} aliases active and previous revisions`);
      }
      validatedInteger(outcome.switchGeneration, `${field}.switchGeneration`, 2);
      parseDigest(outcome.healthReceiptDigest, `${field}.healthReceiptDigest`);
      parseDigest(outcome.migrationReceiptDigest, `${field}.migrationReceiptDigest`);
      break;
    }
    case "runtime_revision_rolled_back": {
      const outcome = validatedExactFields(
        value,
        [
          "kind",
          "activeRevision",
          "previousRevision",
          "switchGeneration",
          "failureReceiptDigest",
        ],
        [],
        field,
        errorCode,
      );
      const activeRevision = parseDigest(
        outcome.activeRevision,
        `${field}.activeRevision`,
      );
      const previousRevision = parseDigest(
        outcome.previousRevision,
        `${field}.previousRevision`,
      );
      if (previousRevision === activeRevision) {
        sessionError(errorCode, `${field} aliases active and previous revisions`);
      }
      validatedInteger(outcome.switchGeneration, `${field}.switchGeneration`, 2);
      parseDigest(outcome.failureReceiptDigest, `${field}.failureReceiptDigest`);
      break;
    }
    default:
      sessionError(errorCode, `${field} has an unknown outcome kind`);
  }
}

export async function checkpointDigest(checkpoint: AgentCheckpoint) {
  const validated = await validateAgentCheckpoint(checkpoint);
  return digestStructuredValue(
    SESSION_CHECKPOINT_DIGEST_DOMAIN,
    SESSION_CHECKPOINT_DIGEST_SCHEMA_VERSION,
    validated,
  );
}

export async function turnInputDigest(input: NormalizedValue) {
  return digestStructuredValue(
    SESSION_TURN_INPUT_DIGEST_DOMAIN,
    SESSION_TURN_INPUT_DIGEST_SCHEMA_VERSION,
    normalizeProtocolValue(input),
  );
}

export async function effectRequestDigest(request: Omit<EffectIntent, "requestDigest">) {
  const digestPayload = {
    service: request.service,
    operation: request.operation,
    replayPolicy: request.replayPolicy,
    payload: normalizeProtocolValue(request.payload),
    ...(request.parentOperationId === undefined
      ? {}
      : { parentOperationId: request.parentOperationId, ordinal: request.ordinal }),
  };
  return digestStructuredValue(
    SESSION_EFFECT_REQUEST_DIGEST_DOMAIN,
    SESSION_EFFECT_REQUEST_DIGEST_SCHEMA_VERSION,
    digestPayload,
  );
}

export function createSessionState(input: CreateSessionStateInput): SessionAggregateState {
  validatedExactFields(
    input,
    [
      "sessionId",
      "tenantId",
      "userId",
      "workspaceId",
      "runtimeRevisionDigest",
      "policySnapshotDigest",
      "emergencyOverlayDigest",
      "engineKind",
      "adapterAbiVersion",
      "checkpointSchemaVersion",
      "placementGeneration",
      "sandboxGeneration",
      "authorizationGeneration",
    ],
    [],
    "initialization",
    "INVALID_ARGUMENT",
  );
  const runtimeRevisionDigest = parseDigest(
    input.runtimeRevisionDigest,
    "runtimeRevisionDigest",
  );
  const state: SessionAggregateState = {
    schemaVersion: SESSION_STATE_SCHEMA_VERSION,
    sessionId: validatedIdentifier(input.sessionId, "sessionId"),
    tenantId: validatedIdentifier(input.tenantId, "tenantId"),
    userId: validatedIdentifier(input.userId, "userId"),
    workspaceId: validatedIdentifier(input.workspaceId, "workspaceId"),
    runtimeRevisionDigest,
    runtimePointer: {
      activeRevision: runtimeRevisionDigest,
      candidateRevision: null,
      previousRevision: null,
      switchGeneration: 1,
    },
    policySnapshotDigest: parseDigest(input.policySnapshotDigest, "policySnapshotDigest"),
    emergencyOverlayDigest: parseDigest(
      input.emergencyOverlayDigest,
      "emergencyOverlayDigest",
    ),
    engineKind: validatedEngineKind(input.engineKind, "engineKind"),
    adapterAbiVersion: validatedInteger(input.adapterAbiVersion, "adapterAbiVersion", 1),
    checkpointSchemaVersion: validatedInteger(
      input.checkpointSchemaVersion,
      "checkpointSchemaVersion",
      1,
    ),
    status: "ready",
    eventSequence: 0,
    publicEventSequence: 0,
    nextTurnSequence: 0,
    activeTurn: null,
    queuedTurns: [],
    terminalTurns: [],
    knownTurnIds: [],
    latestSettledTurn: null,
    effects: [],
    placementGeneration: validatedInteger(
      input.placementGeneration,
      "placementGeneration",
      0,
    ),
    sandboxGeneration: validatedInteger(input.sandboxGeneration, "sandboxGeneration", 0),
    authorizationGeneration: validatedInteger(
      input.authorizationGeneration,
      "authorizationGeneration",
      0,
    ),
    commandReceipts: [],
    publicEvents: [],
    turnAdmissionReceipts: [],
  };
  assertSessionInvariants(state);
  return state;
}

export function migrateSessionState(state: unknown): {
  readonly state: SessionAggregateState;
  readonly migrated: boolean;
} {
  if (
    typeof state !== "object" ||
    state === null ||
    Array.isArray(state) ||
    (state as { readonly schemaVersion?: unknown }).schemaVersion !== 1
  ) {
    return {
      state: state as SessionAggregateState,
      migrated: false,
    };
  }
  const legacy = validatedExactFields(
    state,
    LEGACY_SESSION_STATE_FIELDS,
    [],
    "legacy session state",
    "FAILED_PRECONDITION",
  );
  return {
    state: {
      ...structuredClone(legacy),
      schemaVersion: SESSION_STATE_SCHEMA_VERSION,
      publicEventSequence: 0,
      publicEvents: [],
      turnAdmissionReceipts: [],
    } as unknown as SessionAggregateState,
    migrated: true,
  };
}

export function assertSessionInvariants(state: SessionAggregateState): void {
  validatedNormalizedValue(
    state,
    "session state",
    SESSION_STATE_MAX_ENCODED_BYTES,
    true,
    "FAILED_PRECONDITION",
  );
  validatedExactFields(
    state,
    SESSION_STATE_FIELDS,
    [],
    "session state",
    "FAILED_PRECONDITION",
  );
  if (
    !Array.isArray(state.queuedTurns) ||
    !Array.isArray(state.terminalTurns) ||
    !Array.isArray(state.knownTurnIds) ||
    !Array.isArray(state.effects) ||
    !Array.isArray(state.commandReceipts) ||
    !Array.isArray(state.publicEvents) ||
    !Array.isArray(state.turnAdmissionReceipts)
  ) {
    sessionError("FAILED_PRECONDITION", "session state collections must be arrays");
  }
  if (state.schemaVersion !== SESSION_STATE_SCHEMA_VERSION) {
    sessionError("FAILED_PRECONDITION", "unsupported session state schemaVersion");
  }
  validatedIdentifier(state.sessionId, "state.sessionId");
  validatedIdentifier(state.tenantId, "state.tenantId");
  validatedIdentifier(state.userId, "state.userId");
  validatedIdentifier(state.workspaceId, "state.workspaceId");
  const runtimeRevisionDigest = parseDigest(
    state.runtimeRevisionDigest,
    "state.runtimeRevisionDigest",
  );
  const runtimePointer = validatedExactFields(
    state.runtimePointer,
    [
      "activeRevision",
      "candidateRevision",
      "previousRevision",
      "switchGeneration",
    ],
    [],
    "state.runtimePointer",
    "FAILED_PRECONDITION",
  );
  const activeRevision = parseDigest(
    runtimePointer.activeRevision,
    "state.runtimePointer.activeRevision",
  );
  const candidateRevision =
    runtimePointer.candidateRevision === null
      ? null
      : parseDigest(
          runtimePointer.candidateRevision,
          "state.runtimePointer.candidateRevision",
        );
  const previousRevision =
    runtimePointer.previousRevision === null
      ? null
      : parseDigest(
          runtimePointer.previousRevision,
          "state.runtimePointer.previousRevision",
        );
  validatedInteger(
    runtimePointer.switchGeneration,
    "state.runtimePointer.switchGeneration",
    1,
  );
  if (activeRevision !== runtimeRevisionDigest) {
    sessionError(
      "FAILED_PRECONDITION",
      "runtimePointer.activeRevision does not match runtimeRevisionDigest",
    );
  }
  const pointerRevisions = [activeRevision, candidateRevision, previousRevision].filter(
    (revision): revision is typeof activeRevision => revision !== null,
  );
  if (new Set(pointerRevisions).size !== pointerRevisions.length) {
    sessionError("FAILED_PRECONDITION", "runtime pointer revisions must not alias");
  }
  parseDigest(state.policySnapshotDigest, "state.policySnapshotDigest");
  parseDigest(state.emergencyOverlayDigest, "state.emergencyOverlayDigest");
  validatedEngineKind(state.engineKind, "state.engineKind");
  validatedInteger(state.adapterAbiVersion, "state.adapterAbiVersion", 1);
  validatedInteger(state.checkpointSchemaVersion, "state.checkpointSchemaVersion", 1);
  validatedInteger(state.eventSequence, "state.eventSequence", 0);
  validatedInteger(state.publicEventSequence, "state.publicEventSequence", 0);
  validatedInteger(state.nextTurnSequence, "state.nextTurnSequence", 0);
  validatedInteger(state.placementGeneration, "state.placementGeneration", 0);
  validatedInteger(state.sandboxGeneration, "state.sandboxGeneration", 0);
  validatedInteger(state.authorizationGeneration, "state.authorizationGeneration", 0);
  if (
    state.status !== "created" &&
    state.status !== "starting" &&
    state.status !== "ready" &&
    state.status !== "running" &&
    state.status !== "interrupted" &&
    state.status !== "failed" &&
    state.status !== "closed"
  ) {
    sessionError("FAILED_PRECONDITION", "unknown session status");
  }

  const knownTurns = new Set<string>();
  for (const [index, turnId] of state.knownTurnIds.entries()) {
    const validated = validatedIdentifier(turnId, `state.knownTurnIds[${index}]`);
    if (knownTurns.has(validated)) {
      sessionError("FAILED_PRECONDITION", `duplicate known turn ${validated}`);
    }
    knownTurns.add(validated);
  }
  if (state.nextTurnSequence !== state.knownTurnIds.length) {
    sessionError("FAILED_PRECONDITION", "nextTurnSequence does not match admitted turn count");
  }
  const representedTurnIds = new Set<string>();
  for (const [index, turn] of state.terminalTurns.entries()) {
    validatedExactFields(
      turn,
      [
        "turnId",
        "sequence",
        "input",
        "inputDigest",
        "finalCheckpoint",
        "turnLeaseGeneration",
        "leaseExpiresAt",
        "abortRequested",
        "abortReason",
        "status",
        "result",
        "error",
      ],
      [],
      `state.terminalTurns[${index}]`,
      "FAILED_PRECONDITION",
    );
    if (
      !knownTurns.has(turn.turnId) ||
      state.knownTurnIds[turn.sequence] !== turn.turnId ||
      turn.sequence !== index
    ) {
      sessionError("FAILED_PRECONDITION", "terminal turn history is not FIFO admission order");
    }
    if (representedTurnIds.has(turn.turnId)) {
      sessionError("FAILED_PRECONDITION", "an admitted turn has more than one durable status");
    }
    representedTurnIds.add(turn.turnId);
    validatedIdentifier(turn.turnId, `state.terminalTurns[${index}].turnId`);
    validatedInteger(turn.sequence, `state.terminalTurns[${index}].sequence`, 0);
    validatedNormalizedValue(
      turn.input,
      `state.terminalTurns[${index}].input`,
      SESSION_VALUE_MAX_ENCODED_BYTES,
      true,
      "FAILED_PRECONDITION",
    );
    parseDigest(turn.inputDigest, `terminal turn ${turn.turnId} inputDigest`);
    const finalCheckpoint = parseAgentCheckpoint(turn.finalCheckpoint);
    checkpointMatchesSession(state, finalCheckpoint, turn.turnId, false);
    validatedInteger(turn.turnLeaseGeneration, "terminal turn lease generation", 1);
    validatedInteger(turn.leaseExpiresAt, "terminal turn lease expiry", 1);
    if (typeof turn.abortRequested !== "boolean") {
      sessionError("FAILED_PRECONDITION", "terminal abortRequested must be a boolean");
    }
    if (turn.abortRequested !== (turn.abortReason !== null)) {
      sessionError("FAILED_PRECONDITION", "terminal abortRequested and abortReason disagree");
    }
    if (turn.abortReason !== null) {
      validatedIdentifier(turn.abortReason, "terminal turn abortReason");
    }
    if (
      (turn.status === "completed" || turn.status === "failed") &&
      finalCheckpoint.kind !== "engine"
    ) {
      sessionError("FAILED_PRECONDITION", "terminal engine checkpoint must be engine kind");
    }
    if (turn.status === "completed") {
      parseEngineStepResult({
        kind: "turn_complete",
        checkpoint: finalCheckpoint,
        result: turn.result,
      });
      validatedNormalizedValue(
        turn.result,
        `state.terminalTurns[${index}].result`,
        SESSION_VALUE_MAX_ENCODED_BYTES,
        true,
        "FAILED_PRECONDITION",
      );
      if (turn.error !== null) {
        sessionError("FAILED_PRECONDITION", "completed turn retained a terminal error");
      }
    } else if (turn.status === "failed") {
      parseEngineStepResult({
        kind: "turn_error",
        checkpoint: finalCheckpoint,
        error: turn.error,
      });
      if (turn.error.details !== undefined) {
        validatedNormalizedValue(
          turn.error.details,
          `state.terminalTurns[${index}].error.details`,
          SESSION_VALUE_MAX_ENCODED_BYTES,
          true,
          "FAILED_PRECONDITION",
        );
      }
      if (turn.result !== null) {
        sessionError("FAILED_PRECONDITION", "failed turn retained a terminal result");
      }
    } else if (turn.status === "aborted") {
      if (
        !turn.abortRequested ||
        turn.abortReason === null ||
        turn.result !== null ||
        turn.error !== null
      ) {
        sessionError("FAILED_PRECONDITION", "aborted turn terminal fields disagree");
      }
    } else {
      sessionError("FAILED_PRECONDITION", "unknown terminal turn status");
    }
  }
  const latestTerminal = state.terminalTurns.at(-1)?.turnId ?? null;
  if (state.latestSettledTurn !== latestTerminal) {
    sessionError("FAILED_PRECONDITION", "latestSettledTurn does not match terminal history");
  }
  if (state.latestSettledTurn !== null) {
    validatedIdentifier(state.latestSettledTurn, "state.latestSettledTurn");
  }

  let previousSequence = -1;
  for (const [index, turn] of state.queuedTurns.entries()) {
    validatedExactFields(
      turn,
      [
        "turnId",
        "sequence",
        "status",
        "input",
        "inputDigest",
        "checkpoint",
        "turnLeaseGeneration",
        "leaseExpiresAt",
      ],
      [],
      `state.queuedTurns[${index}]`,
      "FAILED_PRECONDITION",
    );
    if (turn.status !== "queued") {
      sessionError("FAILED_PRECONDITION", "queued turn status must be queued");
    }
    if (!knownTurns.has(turn.turnId)) {
      sessionError("FAILED_PRECONDITION", `queued turn ${turn.turnId} is not known`);
    }
    if (representedTurnIds.has(turn.turnId)) {
      sessionError("FAILED_PRECONDITION", "an admitted turn has more than one durable status");
    }
    representedTurnIds.add(turn.turnId);
    validatedIdentifier(turn.turnId, `state.queuedTurns[${index}].turnId`);
    validatedInteger(turn.sequence, `state.queuedTurns[${index}].sequence`, 0);
    if (turn.sequence <= previousSequence) {
      sessionError("FAILED_PRECONDITION", "queued turn sequence is not strict FIFO");
    }
    if (state.knownTurnIds[turn.sequence] !== turn.turnId) {
      sessionError("FAILED_PRECONDITION", "queued turn sequence does not match admission order");
    }
    previousSequence = turn.sequence;
    const checkpoint = parseAgentCheckpoint(turn.checkpoint);
    checkpointMatchesSession(state, checkpoint, turn.turnId);
    if (checkpoint.kind !== "genesis" || checkpoint.checkpointSequence !== 0) {
      sessionError("FAILED_PRECONDITION", "a queued turn must retain its genesis checkpoint");
    }
    validatedNormalizedValue(
      turn.input,
      `state.queuedTurns[${index}].input`,
      SESSION_VALUE_MAX_ENCODED_BYTES,
      true,
      "FAILED_PRECONDITION",
    );
    parseDigest(turn.inputDigest, `queued turn ${turn.turnId} inputDigest`);
    validatedInteger(turn.turnLeaseGeneration, "queued turn lease generation", 1);
    validatedInteger(turn.leaseExpiresAt, "queued turn lease expiry", 1);
  }

  if (state.activeTurn === null) {
    if (state.status === "running") {
      sessionError("FAILED_PRECONDITION", "a running session requires an active turn");
    }
    if (state.queuedTurns.length !== 0) {
      sessionError("FAILED_PRECONDITION", "a queued turn exists without an active FIFO head");
    }
  } else {
    const active = state.activeTurn;
    validatedExactFields(
      active,
      [
        "turnId",
        "sequence",
        "status",
        "input",
        "inputDigest",
        "checkpoint",
        "turnLeaseGeneration",
        "leaseExpiresAt",
        "abortRequested",
        "abortReason",
        "activeEffectId",
      ],
      [],
      "state.activeTurn",
      "FAILED_PRECONDITION",
    );
    if (active.status !== "active" && active.status !== "needs_confirmation") {
      sessionError("FAILED_PRECONDITION", "unknown active turn status");
    }
    if (!knownTurns.has(active.turnId)) {
      sessionError("FAILED_PRECONDITION", "the active turn is not in knownTurnIds");
    }
    if (state.queuedTurns.some((turn) => turn.turnId === active.turnId)) {
      sessionError("FAILED_PRECONDITION", "the active turn is also queued");
    }
    if (representedTurnIds.has(active.turnId)) {
      sessionError("FAILED_PRECONDITION", "an admitted turn has more than one durable status");
    }
    representedTurnIds.add(active.turnId);
    validatedIdentifier(active.turnId, "state.activeTurn.turnId");
    validatedInteger(active.sequence, "state.activeTurn.sequence", 0);
    if (state.knownTurnIds[active.sequence] !== active.turnId) {
      sessionError("FAILED_PRECONDITION", "active turn sequence does not match admission order");
    }
    if (active.sequence !== state.terminalTurns.length) {
      sessionError("FAILED_PRECONDITION", "active turn does not follow terminal history");
    }
    if (
      state.queuedTurns[0] !== undefined &&
      state.queuedTurns[0].sequence <= active.sequence
    ) {
      sessionError("FAILED_PRECONDITION", "active turn is not the FIFO head");
    }
    const checkpoint = parseAgentCheckpoint(active.checkpoint);
    checkpointMatchesSession(state, checkpoint, active.turnId);
    validatedNormalizedValue(
      active.input,
      "state.activeTurn.input",
      SESSION_VALUE_MAX_ENCODED_BYTES,
      true,
      "FAILED_PRECONDITION",
    );
    parseDigest(active.inputDigest, `active turn ${active.turnId} inputDigest`);
    if (state.status !== "running") {
      sessionError("FAILED_PRECONDITION", "an active turn requires running session status");
    }
    if (active.abortRequested !== (active.abortReason !== null)) {
      sessionError("FAILED_PRECONDITION", "abortRequested and abortReason disagree");
    }
    if (typeof active.abortRequested !== "boolean") {
      sessionError("FAILED_PRECONDITION", "active abortRequested must be a boolean");
    }
    if (active.activeEffectId !== null) {
      validatedIdentifier(active.activeEffectId, "state.activeTurn.activeEffectId");
    }
    if (active.abortReason !== null) {
      validatedIdentifier(active.abortReason, "active turn abortReason");
    }
    validatedInteger(active.turnLeaseGeneration, "active turn lease generation", 1);
    validatedInteger(active.leaseExpiresAt, "active turn lease expiry", 1);
  }

  if (representedTurnIds.size !== knownTurns.size) {
    sessionError(
      "FAILED_PRECONDITION",
      "every admitted turn must have exactly one durable status",
    );
  }
  for (const turnId of knownTurns) {
    if (!representedTurnIds.has(turnId)) {
      sessionError(
        "FAILED_PRECONDITION",
        "every admitted turn must have exactly one durable status",
      );
    }
  }

  const effectIds = new Set<string>();
  const invocationIds = new Set<string>();
  const unconsumedEffects: SessionEffect[] = [];
  for (const [index, effect] of state.effects.entries()) {
    validatedExactFields(
      effect,
      [
        "tenantId",
        "userId",
        "sessionId",
        "turnId",
        "effectId",
        "invocationId",
        "requestDigest",
        "service",
        "operation",
        "replayPolicy",
        "phase",
        "dispatchAttempt",
        "lastDispatch",
        "requestPayload",
        "externalCommitId",
        "resultRef",
        "settlement",
        "consumedAtCheckpointSequence",
        "consumedByAbort",
      ],
      ["parentOperationId", "ordinal"],
      `state.effects[${index}]`,
      "FAILED_PRECONDITION",
    );
    if (effectIds.has(effect.effectId) || invocationIds.has(effect.invocationId)) {
      sessionError("FAILED_PRECONDITION", "effect or invocation identity was reused");
    }
    effectIds.add(effect.effectId);
    invocationIds.add(effect.invocationId);
    if (
      effect.phase !== "prepared" &&
      effect.phase !== "dispatched" &&
      effect.phase !== "externally_committed" &&
      effect.phase !== "blocked" &&
      effect.phase !== "settled"
    ) {
      sessionError("FAILED_PRECONDITION", "unknown effect phase");
    }
    const claimInput = {
      tenantId: effect.tenantId,
      userId: effect.userId,
      sessionId: effect.sessionId,
      turnId: effect.turnId,
      effectId: effect.effectId,
      invocationId: effect.invocationId,
      requestDigest: effect.requestDigest,
      service: effect.service,
      operation: effect.operation,
      replayPolicy: effect.replayPolicy,
      ...(effect.parentOperationId === undefined
        ? {}
        : { parentOperationId: effect.parentOperationId, ordinal: effect.ordinal }),
    };
    parseEffectClaim(claimInput);
    if (
      effect.tenantId !== state.tenantId ||
      effect.userId !== state.userId ||
      effect.sessionId !== state.sessionId ||
      !knownTurns.has(effect.turnId)
    ) {
      sessionError("FAILED_PRECONDITION", "effect authority identity does not match the session");
    }
    validatedNormalizedValue(
      effect.requestPayload,
      `state.effects[${index}].requestPayload`,
      SESSION_VALUE_MAX_ENCODED_BYTES,
      true,
      "FAILED_PRECONDITION",
    );
    validatedInteger(effect.dispatchAttempt, `effect ${effect.effectId} dispatchAttempt`, 0);
    if ((effect.dispatchAttempt === 0) !== (effect.lastDispatch === null)) {
      sessionError("FAILED_PRECONDITION", "dispatch attempt and durable dispatch metadata disagree");
    }
    if (effect.lastDispatch !== null) {
      validatedExactFields(
        effect.lastDispatch,
        [
          "dispatchAttempt",
          "turnLeaseGeneration",
          "placementGeneration",
          "sandboxGeneration",
          "authorizationGeneration",
          "deadline",
          "providerRequestId",
        ],
        [],
        `state.effects[${index}].lastDispatch`,
        "FAILED_PRECONDITION",
      );
      validatedInteger(
        effect.lastDispatch.dispatchAttempt,
        `effect ${effect.effectId} last dispatch attempt`,
        1,
      );
      validatedInteger(
        effect.lastDispatch.turnLeaseGeneration,
        `effect ${effect.effectId} last dispatch turn lease generation`,
        1,
      );
      validatedInteger(
        effect.lastDispatch.placementGeneration,
        `effect ${effect.effectId} last dispatch placement generation`,
        0,
      );
      validatedInteger(
        effect.lastDispatch.sandboxGeneration,
        `effect ${effect.effectId} last dispatch sandbox generation`,
        0,
      );
      validatedInteger(
        effect.lastDispatch.authorizationGeneration,
        `effect ${effect.effectId} last dispatch authorization generation`,
        0,
      );
      validatedInteger(effect.lastDispatch.deadline, `effect ${effect.effectId} deadline`, 1);
      if (effect.lastDispatch.providerRequestId !== null) {
        validatedIdentifier(
          effect.lastDispatch.providerRequestId,
          `effect ${effect.effectId} providerRequestId`,
        );
      }
      if (effect.lastDispatch.dispatchAttempt !== effect.dispatchAttempt) {
        sessionError("FAILED_PRECONDITION", "last dispatch metadata is not the current attempt");
      }
    }
    if (effect.phase === "prepared" && effect.dispatchAttempt !== 0) {
      sessionError("FAILED_PRECONDITION", "a prepared effect cannot have a dispatch attempt");
    }
    if (
      (effect.phase === "dispatched" ||
        effect.phase === "externally_committed" ||
        effect.phase === "blocked") &&
      effect.dispatchAttempt < 1
    ) {
      sessionError("FAILED_PRECONDITION", `${effect.phase} effect lacks a dispatch attempt`);
    }
    if (effect.phase === "blocked" && effect.replayPolicy !== "confirm") {
      sessionError("FAILED_PRECONDITION", "only a confirm effect may be blocked");
    }
    const hasExternalCommitId = effect.externalCommitId !== null;
    const hasResultRef = effect.resultRef !== null;
    if (hasExternalCommitId !== hasResultRef) {
      sessionError("FAILED_PRECONDITION", "external commit proof fields must appear together");
    }
    if (hasExternalCommitId && hasResultRef) {
      validatedIdentifier(effect.externalCommitId, "effect externalCommitId");
      validatedIdentifier(effect.resultRef, "effect resultRef");
    }
    if (effect.phase === "externally_committed" && !hasExternalCommitId) {
      sessionError("FAILED_PRECONDITION", "externally committed effect lacks external commit proof");
    }
    if (
      (effect.phase === "prepared" ||
        effect.phase === "dispatched" ||
        effect.phase === "blocked") &&
      hasExternalCommitId
    ) {
      sessionError("FAILED_PRECONDITION", `${effect.phase} effect retained external commit proof`);
    }
    if ((effect.phase === "settled") !== (effect.settlement !== null)) {
      sessionError("FAILED_PRECONDITION", "settlement payload and effect phase disagree");
    }
    if (effect.settlement !== null) {
      assertEffectSettlement(
        effect.settlement,
        `state.effects[${index}].settlement`,
        "FAILED_PRECONDITION",
      );
    }
    if (effect.consumedAtCheckpointSequence !== null) {
      validatedInteger(
        effect.consumedAtCheckpointSequence,
        `effect ${effect.effectId} consumed checkpoint sequence`,
        1,
      );
      if (effect.phase !== "settled") {
        sessionError("FAILED_PRECONDITION", "only a settled effect can be consumed");
      }
    }
    if (effect.consumedByAbort && effect.phase !== "settled") {
      sessionError("FAILED_PRECONDITION", "abort consumed a non-settled effect");
    }
    if (typeof effect.consumedByAbort !== "boolean") {
      sessionError("FAILED_PRECONDITION", "effect consumedByAbort must be a boolean");
    }
    if (effect.consumedAtCheckpointSequence !== null && effect.consumedByAbort) {
      sessionError("FAILED_PRECONDITION", "an effect settlement was consumed twice");
    }
    if (effect.consumedAtCheckpointSequence === null && !effect.consumedByAbort) {
      unconsumedEffects.push(effect);
    }
  }
  if (unconsumedEffects.length > 1) {
    sessionError("FAILED_PRECONDITION", "more than one external effect is active");
  }
  if (state.activeTurn === null) {
    if (unconsumedEffects.length !== 0) {
      sessionError("FAILED_PRECONDITION", "an effect is active without an active turn");
    }
  } else {
    const activeEffect =
      state.activeTurn.activeEffectId === null
        ? undefined
        : effectById(state, state.activeTurn.activeEffectId);
    if (state.activeTurn.activeEffectId === null && unconsumedEffects.length !== 0) {
      sessionError("FAILED_PRECONDITION", "activeEffectId does not name the active effect");
    }
    if (
      state.activeTurn.activeEffectId !== null &&
      (activeEffect === undefined ||
        unconsumedEffects.length !== 1 ||
        unconsumedEffects[0]?.effectId !== activeEffect.effectId ||
        activeEffect.turnId !== state.activeTurn.turnId)
    ) {
      sessionError("FAILED_PRECONDITION", "active effect and active turn disagree");
    }
    if (
      state.activeTurn.status === "needs_confirmation" &&
      activeEffect?.phase !== "blocked"
    ) {
      sessionError("FAILED_PRECONDITION", "needs_confirmation turn lacks a blocked effect");
    }
    if (
      activeEffect?.phase === "blocked" &&
      state.activeTurn.status !== "needs_confirmation"
    ) {
      sessionError("FAILED_PRECONDITION", "blocked effect and turn status disagree");
    }
  }

  if (
    state.publicEvents.length !== state.publicEventSequence ||
    state.turnAdmissionReceipts.length !== state.publicEventSequence
  ) {
    sessionError(
      "FAILED_PRECONDITION",
      "publicEventSequence does not match the public event journal and admission receipts",
    );
  }
  const inputDigestByTurnId = new Map<string, string>();
  for (const turn of state.terminalTurns) {
    inputDigestByTurnId.set(turn.turnId, turn.inputDigest);
  }
  for (const turn of state.queuedTurns) {
    inputDigestByTurnId.set(turn.turnId, turn.inputDigest);
  }
  if (state.activeTurn !== null) {
    inputDigestByTurnId.set(state.activeTurn.turnId, state.activeTurn.inputDigest);
  }
  const publicTurnIds = new Set<string>();
  const idempotencyKeyDigests = new Set<string>();
  for (let index = 0; index < state.publicEventSequence; index += 1) {
    const event = state.publicEvents[index];
    const receipt = state.turnAdmissionReceipts[index];
    if (event === undefined || receipt === undefined) {
      sessionError("FAILED_PRECONDITION", "public event journal has a gap");
    }
    validatedExactFields(
      event,
      ["sequence", "type", "turnId", "turnSequence", "status"],
      [],
      `state.publicEvents[${index}]`,
      "FAILED_PRECONDITION",
    );
    validatedInteger(event.sequence, `state.publicEvents[${index}].sequence`, 1);
    if (event.sequence !== index + 1 || event.type !== "turn.accepted") {
      sessionError("FAILED_PRECONDITION", "public events are not gap-free turn.accepted events");
    }
    validatedIdentifier(event.turnId, `state.publicEvents[${index}].turnId`);
    validatedInteger(event.turnSequence, `state.publicEvents[${index}].turnSequence`, 0);
    if (
      state.knownTurnIds[event.turnSequence] !== event.turnId ||
      (event.status !== "active" && event.status !== "queued") ||
      publicTurnIds.has(event.turnId)
    ) {
      sessionError("FAILED_PRECONDITION", "public turn.accepted event is inconsistent");
    }
    publicTurnIds.add(event.turnId);

    validatedExactFields(
      receipt,
      [
        "idempotencyKeyDigest",
        "requestDigest",
        "inputDigest",
        "turnId",
        "turnSequence",
        "activated",
        "publicEventSequence",
      ],
      [],
      `state.turnAdmissionReceipts[${index}]`,
      "FAILED_PRECONDITION",
    );
    const idempotencyKeyDigest = parseDigest(
      receipt.idempotencyKeyDigest,
      `state.turnAdmissionReceipts[${index}].idempotencyKeyDigest`,
    );
    parseDigest(
      receipt.requestDigest,
      `state.turnAdmissionReceipts[${index}].requestDigest`,
    );
    parseDigest(receipt.inputDigest, `state.turnAdmissionReceipts[${index}].inputDigest`);
    validatedIdentifier(receipt.turnId, `state.turnAdmissionReceipts[${index}].turnId`);
    validatedInteger(
      receipt.turnSequence,
      `state.turnAdmissionReceipts[${index}].turnSequence`,
      0,
    );
    validatedInteger(
      receipt.publicEventSequence,
      `state.turnAdmissionReceipts[${index}].publicEventSequence`,
      1,
    );
    if (typeof receipt.activated !== "boolean") {
      sessionError("FAILED_PRECONDITION", "admission receipt activated must be a boolean");
    }
    if (idempotencyKeyDigests.has(idempotencyKeyDigest)) {
      sessionError("FAILED_PRECONDITION", "duplicate public idempotency key receipt");
    }
    idempotencyKeyDigests.add(idempotencyKeyDigest);
    if (
      receipt.publicEventSequence !== event.sequence ||
      receipt.turnId !== event.turnId ||
      receipt.turnSequence !== event.turnSequence ||
      receipt.activated !== (event.status === "active") ||
      inputDigestByTurnId.get(receipt.turnId) !== receipt.inputDigest
    ) {
      sessionError("FAILED_PRECONDITION", "public admission receipt is inconsistent");
    }
  }

  const commandIds = new Set<string>();
  if (state.commandReceipts.length !== state.eventSequence) {
    sessionError("FAILED_PRECONDITION", "eventSequence does not match command receipt count");
  }
  for (const [index, receipt] of state.commandReceipts.entries()) {
    validatedExactFields(
      receipt,
      ["commandId", "commandDigest", "committedEventSequence", "outcome"],
      [],
      `state.commandReceipts[${index}]`,
      "FAILED_PRECONDITION",
    );
    if (commandIds.has(receipt.commandId)) {
      sessionError("FAILED_PRECONDITION", "duplicate command receipt");
    }
    commandIds.add(receipt.commandId);
    validatedIdentifier(receipt.commandId, "receipt.commandId");
    parseDigest(receipt.commandDigest, "receipt.commandDigest");
    validatedInteger(receipt.committedEventSequence, "receipt event sequence", 1);
    if (receipt.committedEventSequence !== index + 1) {
      sessionError("FAILED_PRECONDITION", "command receipts are not in eventSequence order");
    }
    assertSessionCommandOutcome(
      receipt.outcome,
      `state.commandReceipts[${index}].outcome`,
      "FAILED_PRECONDITION",
    );
  }

  let receiptActiveRevision: typeof activeRevision | null = null;
  let receiptCandidateRevision: typeof activeRevision | null = null;
  let receiptPreviousRevision: typeof activeRevision | null = null;
  let receiptSwitchGeneration = 1;
  const activatedRuntimeRevisions = new Set<typeof activeRevision>();
  for (const receipt of state.commandReceipts) {
    const receiptOutcome = receipt.outcome;
    switch (receiptOutcome.kind) {
      case "runtime_revision_staged":
        receiptActiveRevision ??= receiptOutcome.activeRevision;
        if (
          receiptOutcome.activeRevision !== receiptActiveRevision ||
          receiptOutcome.switchGeneration !== receiptSwitchGeneration ||
          receiptCandidateRevision !== null ||
          receiptOutcome.candidateRevision === receiptActiveRevision ||
          receiptOutcome.candidateRevision === receiptPreviousRevision
        ) {
          sessionError(
            "FAILED_PRECONDITION",
            "runtime revision staging receipt does not follow pointer history",
          );
        }
        activatedRuntimeRevisions.add(receiptActiveRevision);
        receiptCandidateRevision = receiptOutcome.candidateRevision;
        break;
      case "runtime_candidate_discarded":
        if (
          receiptActiveRevision === null ||
          receiptOutcome.activeRevision !== receiptActiveRevision ||
          receiptOutcome.candidateRevision !== receiptCandidateRevision ||
          receiptOutcome.switchGeneration !== receiptSwitchGeneration
        ) {
          sessionError(
            "FAILED_PRECONDITION",
            "runtime candidate discard receipt does not follow pointer history",
          );
        }
        receiptCandidateRevision = null;
        break;
      case "runtime_revision_activated": {
        if (
          receiptActiveRevision === null ||
          receiptOutcome.previousRevision !== receiptActiveRevision ||
          receiptOutcome.activeRevision !== receiptCandidateRevision ||
          receiptOutcome.switchGeneration !== receiptSwitchGeneration + 1
        ) {
          sessionError(
            "FAILED_PRECONDITION",
            "runtime revision activation receipt does not follow pointer history",
          );
        }
        const priorActiveRevision: typeof activeRevision = receiptActiveRevision;
        receiptActiveRevision = receiptOutcome.activeRevision;
        receiptCandidateRevision = null;
        receiptPreviousRevision = priorActiveRevision;
        receiptSwitchGeneration += 1;
        activatedRuntimeRevisions.add(receiptActiveRevision);
        break;
      }
      case "runtime_revision_rolled_back": {
        if (
          receiptActiveRevision === null ||
          receiptCandidateRevision !== null ||
          receiptPreviousRevision === null ||
          receiptOutcome.activeRevision !== receiptPreviousRevision ||
          receiptOutcome.previousRevision !== receiptActiveRevision ||
          receiptOutcome.switchGeneration !== receiptSwitchGeneration + 1
        ) {
          sessionError(
            "FAILED_PRECONDITION",
            "runtime revision rollback receipt does not follow pointer history",
          );
        }
        const priorActiveRevision: typeof activeRevision = receiptActiveRevision;
        receiptActiveRevision = receiptPreviousRevision;
        receiptPreviousRevision = priorActiveRevision;
        receiptSwitchGeneration += 1;
        activatedRuntimeRevisions.add(receiptActiveRevision);
        break;
      }
      default:
        break;
    }
  }
  receiptActiveRevision ??= activeRevision;
  activatedRuntimeRevisions.add(receiptActiveRevision);
  if (
    receiptActiveRevision !== activeRevision ||
    receiptCandidateRevision !== candidateRevision ||
    receiptPreviousRevision !== previousRevision ||
    receiptSwitchGeneration !== state.runtimePointer.switchGeneration
  ) {
    sessionError(
      "FAILED_PRECONDITION",
      "runtime pointer does not match its durable command receipt history",
    );
  }
  for (const turn of state.terminalTurns) {
    if (!activatedRuntimeRevisions.has(turn.finalCheckpoint.runtimeRevisionDigest)) {
      sessionError(
        "FAILED_PRECONDITION",
        `terminal turn ${turn.turnId} names a runtime revision that was never active`,
      );
    }
  }
}

export async function validateSessionState(state: SessionAggregateState): Promise<void> {
  assertSessionInvariants(state);
  if (state.activeTurn !== null) {
    await validateAgentCheckpoint(state.activeTurn.checkpoint);
    if ((await turnInputDigest(state.activeTurn.input)) !== state.activeTurn.inputDigest) {
      sessionError("DIGEST_MISMATCH", "active turn inputDigest does not bind its input");
    }
  }
  for (const turn of state.queuedTurns) {
    await validateAgentCheckpoint(turn.checkpoint);
    if ((await turnInputDigest(turn.input)) !== turn.inputDigest) {
      sessionError("DIGEST_MISMATCH", `queued turn ${turn.turnId} inputDigest is invalid`);
    }
  }
  for (const turn of state.terminalTurns) {
    await validateAgentCheckpoint(turn.finalCheckpoint);
    if ((await turnInputDigest(turn.input)) !== turn.inputDigest) {
      sessionError("DIGEST_MISMATCH", `terminal turn ${turn.turnId} inputDigest is invalid`);
    }
  }
  for (const effect of state.effects) {
    const requestDigest = await effectRequestDigest({
      service: effect.service,
      operation: effect.operation,
      replayPolicy: effect.replayPolicy,
      payload: effect.requestPayload,
      ...(effect.parentOperationId === undefined
        ? {}
        : { parentOperationId: effect.parentOperationId, ordinal: effect.ordinal }),
    });
    if (requestDigest !== effect.requestDigest) {
      sessionError("DIGEST_MISMATCH", `effect ${effect.effectId} requestDigest is invalid`);
    }
  }
}

export function replaySessionPublicEvents(
  state: SessionAggregateState,
  afterSequenceInput: unknown,
  limitInput: unknown,
): SessionPublicEventReplay {
  assertSessionInvariants(state);
  const afterSequence = validatedInteger(afterSequenceInput, "afterSequence", 0);
  const limit = validatedInteger(limitInput, "limit", 1);
  if (afterSequence > state.publicEventSequence) {
    sessionError("INVALID_ARGUMENT", "afterSequence is ahead of the public event cursor");
  }
  if (limit > SESSION_PUBLIC_EVENT_REPLAY_MAX_EVENTS) {
    sessionError(
      "INVALID_ARGUMENT",
      `limit must not exceed ${SESSION_PUBLIC_EVENT_REPLAY_MAX_EVENTS}`,
    );
  }
  return {
    snapshot: {
      sessionId: state.sessionId,
      activeTurnId: state.activeTurn?.turnId ?? null,
      turnStatus: state.activeTurn?.status ?? null,
      lastEventSequence: state.publicEventSequence,
    },
    events: structuredClone(
      state.publicEvents.slice(afterSequence, afterSequence + limit),
    ),
  };
}

export async function applySessionCommand(
  state: SessionAggregateState,
  command: SessionCommand,
): Promise<ApplySessionCommandResult> {
  await validateSessionState(state);
  validatedIdentifier(command.commandId, "commandId");
  validatedInteger(command.expectedEventSequence, "expectedEventSequence", 0);

  let commandFields: readonly string[];
  let optionalCommandFields: readonly string[] = [];
  switch (command.kind) {
    case "enqueue_turn":
      commandFields = [
        "kind",
        "commandId",
        "expectedEventSequence",
        "transactionTime",
        "turnId",
        "input",
        "inputDigest",
        "genesisCheckpoint",
        "turnLeaseGeneration",
        "leaseExpiresAt",
      ];
      optionalCommandFields = ["publicAdmission"];
      break;
    case "commit_engine_step":
      commandFields = [
        "kind",
        "commandId",
        "expectedEventSequence",
        "turnId",
        "fence",
        "transactionTime",
        "consumedSettlementEffectId",
        "effectIdentity",
        "step",
      ];
      break;
    case "dispatch_effect":
    case "recover_effect":
      commandFields = [
        "kind",
        "commandId",
        "expectedEventSequence",
        "turnId",
        "effectId",
        "invocationId",
        "requestDigest",
        "fence",
        "transactionTime",
        "deadline",
      ];
      optionalCommandFields = ["providerRequestId"];
      break;
    case "record_external_commit":
      commandFields = [
        "kind",
        "commandId",
        "expectedEventSequence",
        "turnId",
        "effectId",
        "invocationId",
        "requestDigest",
        "dispatchAttempt",
        "fence",
        "externalCommitId",
        "resultRef",
      ];
      break;
    case "settle_effect":
      commandFields = [
        "kind",
        "commandId",
        "expectedEventSequence",
        "turnId",
        "effectId",
        "invocationId",
        "requestDigest",
        "dispatchAttempt",
        "fence",
        "settlement",
      ];
      break;
    case "resolve_confirmation":
      commandFields = [
        "kind",
        "commandId",
        "expectedEventSequence",
        "turnId",
        "effectId",
        "invocationId",
        "requestDigest",
        "fence",
        "decision",
        "transactionTime",
        "deadline",
      ];
      optionalCommandFields = ["providerRequestId"];
      break;
    case "request_abort":
      commandFields = [
        "kind",
        "commandId",
        "expectedEventSequence",
        "turnId",
        "fence",
        "transactionTime",
        "reason",
      ];
      break;
    case "finalize_abort":
      commandFields = [
        "kind",
        "commandId",
        "expectedEventSequence",
        "turnId",
        "fence",
        "transactionTime",
      ];
      break;
    case "rotate_turn_lease":
      commandFields = [
        "kind",
        "commandId",
        "expectedEventSequence",
        "turnId",
        "fence",
        "transactionTime",
        "nextTurnLeaseGeneration",
        "nextLeaseExpiresAt",
      ];
      break;
    case "rotate_generations":
      commandFields = [
        "kind",
        "commandId",
        "expectedEventSequence",
        "nextPlacementGeneration",
        "nextSandboxGeneration",
        "nextAuthorizationGeneration",
        "nextEmergencyOverlayDigest",
      ];
      break;
    case "stage_runtime_revision":
      commandFields = [
        "kind",
        "commandId",
        "expectedEventSequence",
        "candidateRevision",
      ];
      break;
    case "discard_runtime_candidate":
      commandFields = [
        "kind",
        "commandId",
        "expectedEventSequence",
        "expectedCandidateRevision",
        "failureReceiptDigest",
      ];
      break;
    case "activate_runtime_revision":
      commandFields = [
        "kind",
        "commandId",
        "expectedEventSequence",
        "expectedActiveRevision",
        "expectedCandidateRevision",
        "expectedSwitchGeneration",
        "healthReceiptDigest",
        "migrationReceiptDigest",
      ];
      break;
    case "rollback_runtime_revision":
      commandFields = [
        "kind",
        "commandId",
        "expectedEventSequence",
        "expectedActiveRevision",
        "expectedPreviousRevision",
        "expectedSwitchGeneration",
        "failureReceiptDigest",
      ];
      break;
    default:
      sessionError("INVALID_ARGUMENT", "unknown session command kind");
  }
  validatedExactFields(
    command,
    commandFields,
    optionalCommandFields,
    command.kind,
    "INVALID_ARGUMENT",
  );
  validatedNormalizedValue(
    command,
    "command",
    SESSION_COMMAND_MAX_ENCODED_BYTES,
    false,
    "INVALID_ARGUMENT",
  );

  let commandDigest;
  try {
    commandDigest = await digestStructuredValue(
      "circulusd.state-app.session-command",
      SESSION_COMMAND_SCHEMA_VERSION,
      command,
    );
  } catch (error) {
    if (error instanceof ProtocolValidationError) {
      sessionError("INVALID_ARGUMENT", `command is not serializable: ${error.message}`);
    }
    throw error;
  }

  let validatedPublicAdmission:
    | {
        readonly idempotencyKeyDigest: Digest;
        readonly requestDigest: Digest;
        readonly input: NormalizedValue;
        readonly inputDigest: Digest;
      }
    | undefined;
  if (command.kind === "enqueue_turn" && command.publicAdmission !== undefined) {
    const admission = validatedExactFields(
      command.publicAdmission,
      ["authorizationGeneration", "idempotencyKeyDigest", "requestDigest"],
      [],
      "publicAdmission",
      "INVALID_ARGUMENT",
    );
    const authorizationGeneration = validatedInteger(
      admission.authorizationGeneration,
      "publicAdmission.authorizationGeneration",
      0,
    );
    if (authorizationGeneration !== state.authorizationGeneration) {
      sessionError("STALE_GENERATION", "public turn admission authority is stale");
    }
    const input = validatedNormalizedValue(
      command.input,
      "input",
      SESSION_VALUE_MAX_ENCODED_BYTES,
      false,
      "INVALID_ARGUMENT",
    );
    const inputDigest = parseDigest(command.inputDigest, "inputDigest");
    if ((await turnInputDigest(input)) !== inputDigest) {
      sessionError("DIGEST_MISMATCH", "inputDigest does not bind the normalized turn input");
    }
    validatedPublicAdmission = {
      idempotencyKeyDigest: parseDigest(
        admission.idempotencyKeyDigest,
        "publicAdmission.idempotencyKeyDigest",
      ),
      requestDigest: parseDigest(
        admission.requestDigest,
        "publicAdmission.requestDigest",
      ),
      input,
      inputDigest,
    };
    const idempotencyKeyDigest = validatedPublicAdmission.idempotencyKeyDigest;
    const admissionReceipt = state.turnAdmissionReceipts.find(
      (receipt) => receipt.idempotencyKeyDigest === idempotencyKeyDigest,
    );
    if (admissionReceipt !== undefined) {
      if (
        admissionReceipt.requestDigest !== validatedPublicAdmission.requestDigest ||
        admissionReceipt.inputDigest !== validatedPublicAdmission.inputDigest
      ) {
        sessionError(
          "IDEMPOTENCY_CONFLICT",
          "public idempotency key was reused with a different semantic request",
        );
      }
      return {
        state,
        outcome: {
          kind: "turn_enqueued",
          turnId: admissionReceipt.turnId,
          turnSequence: admissionReceipt.turnSequence,
          activated: admissionReceipt.activated,
        },
        commandDigest,
        replayed: true,
      };
    }
  }

  const existingReceipt = state.commandReceipts.find(
    (receipt) => receipt.commandId === command.commandId,
  );
  if (existingReceipt !== undefined) {
    if (existingReceipt.commandDigest !== commandDigest) {
      sessionError(
        "IDEMPOTENCY_CONFLICT",
        `commandId ${command.commandId} was reused with a different digest`,
      );
    }
    const receiptOutcome = existingReceipt.outcome;
    const dispatchPermitClaims =
      receiptOutcome.kind === "effect_dispatched"
        ? receiptOutcome.dispatchPermitClaims
        : receiptOutcome.kind === "effect_recovered" && receiptOutcome.action === "retry"
          ? receiptOutcome.dispatchPermitClaims
          : receiptOutcome.kind === "confirmation_resolved" &&
              receiptOutcome.decision === "retry"
            ? receiptOutcome.dispatchPermitClaims
            : undefined;
    if (dispatchPermitClaims !== undefined) {
      const active = state.activeTurn;
      if (
        active === null ||
        dispatchPermitClaims.turnLeaseGeneration !== active.turnLeaseGeneration ||
        dispatchPermitClaims.placementGeneration !== state.placementGeneration ||
        dispatchPermitClaims.sandboxGeneration !== state.sandboxGeneration ||
        dispatchPermitClaims.authorizationGeneration !== state.authorizationGeneration
      ) {
        sessionError(
          "STALE_GENERATION",
          "a dispatch capability receipt cannot cross a generation rotation",
        );
      }
      if (active.abortRequested) {
        sessionError("ABORTED", "an aborted turn cannot replay a dispatch capability");
      }
      const effect = effectById(state, dispatchPermitClaims.effectId);
      if (
        active.activeEffectId !== dispatchPermitClaims.effectId ||
        effect === undefined ||
        effect.turnId !== active.turnId ||
        effect.phase !== "dispatched"
      ) {
        sessionError(
          "FAILED_PRECONDITION",
          "the dispatch capability receipt is no longer active",
        );
      }
      if (
        effect.dispatchAttempt !== dispatchPermitClaims.dispatchAttempt ||
        effect.lastDispatch?.dispatchAttempt !== dispatchPermitClaims.dispatchAttempt
      ) {
        sessionError(
          "STALE_DISPATCH_ATTEMPT",
          "the dispatch capability receipt names an older attempt",
        );
      }
      if (
        effect.requestDigest !== dispatchPermitClaims.requestDigest ||
        effect.invocationId !== dispatchPermitClaims.invocationId ||
        effect.lastDispatch.deadline !== dispatchPermitClaims.deadline ||
        effect.lastDispatch.turnLeaseGeneration !==
          dispatchPermitClaims.turnLeaseGeneration ||
        effect.lastDispatch.placementGeneration !== dispatchPermitClaims.placementGeneration ||
        effect.lastDispatch.sandboxGeneration !== dispatchPermitClaims.sandboxGeneration ||
        effect.lastDispatch.authorizationGeneration !==
          dispatchPermitClaims.authorizationGeneration
      ) {
        sessionError(
          "FAILED_PRECONDITION",
          "the dispatch capability receipt does not match durable dispatch metadata",
        );
      }
    }
    return {
      state,
      outcome: structuredClone(existingReceipt.outcome),
      commandDigest,
      replayed: true,
    };
  }
  if (command.expectedEventSequence !== state.eventSequence) {
    sessionError(
      "CONFLICT",
      `expected eventSequence ${command.expectedEventSequence}, current is ${state.eventSequence}`,
    );
  }

  if ("fence" in command) {
    const fenceFields = [
      "turnLeaseGeneration",
      "placementGeneration",
      "sandboxGeneration",
      "authorizationGeneration",
    ];
    for (const key of Reflect.ownKeys(command.fence)) {
      if (typeof key !== "string" || !fenceFields.includes(key)) {
        sessionError("INVALID_ARGUMENT", `unknown field ${String(key)} on fence`);
      }
    }
    for (const field of fenceFields) {
      if (!Object.prototype.hasOwnProperty.call(command.fence, field)) {
        sessionError("INVALID_ARGUMENT", `missing field ${field} on fence`);
      }
    }
    const active = state.activeTurn;
    if (active === null || active.turnId !== command.turnId) {
      sessionError("NOT_FOUND", `turn ${command.turnId} is not active`);
    }
    const fields = [
      ["turnLeaseGeneration", command.fence.turnLeaseGeneration, active.turnLeaseGeneration],
      ["placementGeneration", command.fence.placementGeneration, state.placementGeneration],
      ["sandboxGeneration", command.fence.sandboxGeneration, state.sandboxGeneration],
      [
        "authorizationGeneration",
        command.fence.authorizationGeneration,
        state.authorizationGeneration,
      ],
    ] as const;
    for (const [name, received, current] of fields) {
      validatedInteger(received, `fence.${name}`, 0);
      if (received !== current) {
        sessionError("STALE_GENERATION", `${name} is stale`);
      }
    }
    if (
      active.status === "needs_confirmation" &&
      command.kind !== "resolve_confirmation" &&
      command.kind !== "request_abort" &&
      command.kind !== "record_external_commit" &&
      command.kind !== "rotate_turn_lease"
    ) {
      sessionError("NEEDS_CONFIRMATION", "the active effect requires explicit confirmation");
    }
  }

  const next = structuredClone(state);
  let outcome: SessionCommandOutcome;
  let turnPromotionTime: number | null = null;

  switch (command.kind) {
    case "enqueue_turn": {
      if (next.runtimePointer.candidateRevision !== null) {
        sessionError(
          "FAILED_PRECONDITION",
          "new turn admission is frozen while a runtime revision candidate is staged",
        );
      }
      if (next.activeTurn?.status === "needs_confirmation") {
        sessionError(
          "NEEDS_CONFIRMATION",
          "a blocked confirm effect prevents later turn admission",
        );
      }
      const turnId = validatedIdentifier(command.turnId, "turnId");
      if (next.knownTurnIds.includes(turnId)) {
        sessionError("ALREADY_EXISTS", `turn ${turnId} already exists`);
      }
      const transactionTime = validatedInteger(
        command.transactionTime,
        "transactionTime",
        0,
      );
      const input = validatedPublicAdmission?.input ?? validatedNormalizedValue(
        command.input,
        "input",
        SESSION_VALUE_MAX_ENCODED_BYTES,
        false,
        "INVALID_ARGUMENT",
      );
      const inputDigest = validatedPublicAdmission?.inputDigest ?? parseDigest(
        command.inputDigest,
        "inputDigest",
      );
      if (
        validatedPublicAdmission === undefined &&
        (await turnInputDigest(input)) !== inputDigest
      ) {
        sessionError("DIGEST_MISMATCH", "inputDigest does not bind the normalized turn input");
      }
      const turnLeaseGeneration = validatedInteger(
        command.turnLeaseGeneration,
        "turnLeaseGeneration",
        1,
      );
      const leaseExpiresAt = validatedInteger(command.leaseExpiresAt, "leaseExpiresAt", 1);
      if (leaseExpiresAt <= transactionTime) {
        sessionError(
          "FAILED_PRECONDITION",
          "turn admission requires transactionTime < leaseExpiresAt",
        );
      }
      let checkpoint;
      try {
        checkpoint = await validateAgentCheckpoint(command.genesisCheckpoint);
      } catch (error) {
        if (error instanceof ProtocolValidationError) {
          sessionError("DIGEST_MISMATCH", `invalid genesis checkpoint: ${error.message}`);
        }
        throw error;
      }
      checkpointMatchesSession(next, checkpoint, turnId);
      if (checkpoint.kind !== "genesis") {
        sessionError("FAILED_PRECONDITION", "a newly admitted turn requires a genesis checkpoint");
      }
      const queuedTurn = {
        turnId,
        sequence: next.nextTurnSequence,
        status: "queued" as const,
        input,
        inputDigest,
        checkpoint,
        turnLeaseGeneration,
        leaseExpiresAt,
      };
      next.nextTurnSequence += 1;
      next.knownTurnIds.push(turnId);
      const activated = next.activeTurn === null;
      if (activated) {
        next.activeTurn = {
          ...queuedTurn,
          status: "active",
          abortRequested: false,
          abortReason: null,
          activeEffectId: null,
        };
        next.status = "running";
      } else {
        next.queuedTurns.push(queuedTurn);
      }
      outcome = {
        kind: "turn_enqueued",
        turnId,
        turnSequence: queuedTurn.sequence,
        activated,
      };
      if (validatedPublicAdmission !== undefined) {
        next.publicEventSequence += 1;
        next.publicEvents.push({
          sequence: next.publicEventSequence,
          type: "turn.accepted",
          turnId,
          turnSequence: queuedTurn.sequence,
          status: activated ? "active" : "queued",
        });
        const admissionReceipt: TurnAdmissionReceipt = {
          idempotencyKeyDigest: validatedPublicAdmission.idempotencyKeyDigest,
          requestDigest: validatedPublicAdmission.requestDigest,
          inputDigest,
          turnId,
          turnSequence: queuedTurn.sequence,
          activated,
          publicEventSequence: next.publicEventSequence,
        };
        next.turnAdmissionReceipts.push(admissionReceipt);
      }
      break;
    }

    case "commit_engine_step": {
      const active = next.activeTurn;
      if (active === null || active.turnId !== command.turnId) {
        sessionError("NOT_FOUND", `turn ${command.turnId} is not active`);
      }
      const transactionTime = validatedInteger(
        command.transactionTime,
        "transactionTime",
        0,
      );
      if (transactionTime >= active.leaseExpiresAt) {
        sessionError(
          "FAILED_PRECONDITION",
          "engine step commit requires transactionTime < leaseExpiresAt",
        );
      }
      if (active.abortRequested) {
        sessionError("ABORTED", "an aborted turn cannot commit another engine step");
      }
      let step;
      try {
        step = parseEngineStepResult(command.step);
        await validateAgentCheckpoint(step.checkpoint);
      } catch (error) {
        if (error instanceof ProtocolValidationError) {
          sessionError("INVALID_ARGUMENT", `invalid engine step: ${error.message}`);
        }
        throw error;
      }
      if (step.kind === "effect_request") {
        validatedNormalizedValue(
          step.request.payload,
          "engine step effect request payload",
          SESSION_VALUE_MAX_ENCODED_BYTES,
          true,
          "INVALID_ARGUMENT",
        );
      } else if (step.kind === "turn_complete") {
        validatedNormalizedValue(
          step.result,
          "engine step turn result",
          SESSION_VALUE_MAX_ENCODED_BYTES,
          true,
          "INVALID_ARGUMENT",
        );
      } else if (step.kind === "turn_error" && step.error.details !== undefined) {
        validatedNormalizedValue(
          step.error.details,
          "engine step error details",
          SESSION_VALUE_MAX_ENCODED_BYTES,
          true,
          "INVALID_ARGUMENT",
        );
      }
      checkpointMatchesSession(next, step.checkpoint, active.turnId);
      if (step.checkpoint.kind !== "engine") {
        sessionError("FAILED_PRECONDITION", "an engine step must commit an engine checkpoint");
      }
      if (step.checkpoint.checkpointSequence !== active.checkpoint.checkpointSequence + 1) {
        sessionError("FAILED_PRECONDITION", "checkpointSequence must increment by exactly one");
      }
      const predecessorDigest = await checkpointDigest(active.checkpoint);
      if (step.checkpoint.predecessorDigest !== predecessorDigest) {
        sessionError(
          "DIGEST_MISMATCH",
          "checkpoint predecessorDigest does not match durable state",
        );
      }
      let consumedEffectId: string | null = null;
      if (active.activeEffectId === null) {
        if (command.consumedSettlementEffectId !== null) {
          sessionError("FAILED_PRECONDITION", "no active settlement exists to consume");
        }
      } else {
        const effect = effectById(next, active.activeEffectId);
        if (effect === undefined || effect.phase !== "settled") {
          sessionError("FAILED_PRECONDITION", "the active effect has not settled");
        }
        if (command.consumedSettlementEffectId !== effect.effectId) {
          sessionError(
            "FAILED_PRECONDITION",
            "the engine step did not consume the active settlement",
          );
        }
        if (effect.consumedAtCheckpointSequence !== null || effect.consumedByAbort) {
          sessionError("FAILED_PRECONDITION", "the settlement was already consumed");
        }
        effect.consumedAtCheckpointSequence = step.checkpoint.checkpointSequence;
        active.activeEffectId = null;
        consumedEffectId = effect.effectId;
      }

      let preparedEffectId: string | null = null;
      if (step.kind === "effect_request") {
        if (command.effectIdentity === null) {
          sessionError("INVALID_ARGUMENT", "effect_request requires effectIdentity");
        }
        const effectIdentityFields = ["effectId", "invocationId"];
        for (const key of Reflect.ownKeys(command.effectIdentity)) {
          if (typeof key !== "string" || !effectIdentityFields.includes(key)) {
            sessionError(
              "INVALID_ARGUMENT",
              `unknown field ${String(key)} on effectIdentity`,
            );
          }
        }
        const effectId = validatedIdentifier(
          command.effectIdentity.effectId,
          "effectIdentity.effectId",
        );
        const invocationId = validatedIdentifier(
          command.effectIdentity.invocationId,
          "effectIdentity.invocationId",
        );
        const requestDigest = await effectRequestDigest({
          service: step.request.service,
          operation: step.request.operation,
          replayPolicy: step.request.replayPolicy,
          payload: step.request.payload,
          ...(step.request.parentOperationId === undefined
            ? {}
            : {
                parentOperationId: step.request.parentOperationId,
                ordinal: step.request.ordinal,
              }),
        });
        if (step.request.requestDigest !== requestDigest) {
          sessionError(
            "DIGEST_MISMATCH",
            "requestDigest does not bind the normalized effect intent",
          );
        }
        if (
          next.effects.some(
            (effect) => effect.effectId === effectId || effect.invocationId === invocationId,
          )
        ) {
          sessionError("ALREADY_EXISTS", "effectId or invocationId was already used");
        }
        const claimSource = {
          tenantId: next.tenantId,
          userId: next.userId,
          sessionId: next.sessionId,
          turnId: active.turnId,
          effectId,
          invocationId,
          requestDigest,
          service: step.request.service,
          operation: step.request.operation,
          replayPolicy: step.request.replayPolicy,
          ...(step.request.parentOperationId === undefined
            ? {}
            : {
                parentOperationId: step.request.parentOperationId,
                ordinal: step.request.ordinal,
              }),
        };
        const claim = parseEffectClaim(claimSource);
        next.effects.push({
          ...claim,
          phase: "prepared",
          dispatchAttempt: 0,
          lastDispatch: null,
          requestPayload: structuredClone(step.request.payload),
          externalCommitId: null,
          resultRef: null,
          settlement: null,
          consumedAtCheckpointSequence: null,
          consumedByAbort: false,
        });
        active.activeEffectId = effectId;
        preparedEffectId = effectId;
      } else if (command.effectIdentity !== null) {
        sessionError("INVALID_ARGUMENT", `${step.kind} cannot allocate an effect identity`);
      }

      active.checkpoint = step.checkpoint;
      let status: "active" | "completed" | "failed" = "active";
      if (step.kind === "turn_complete" || step.kind === "turn_error") {
        if (active.activeEffectId !== null) {
          sessionError(
            "FAILED_PRECONDITION",
            "a terminal engine step cannot retain an active effect",
          );
        }
        status = step.kind === "turn_complete" ? "completed" : "failed";
        turnPromotionTime = transactionTime;
        const terminalTurnBase = {
          turnId: active.turnId,
          sequence: active.sequence,
          input: structuredClone(active.input),
          inputDigest: active.inputDigest,
          finalCheckpoint: step.checkpoint,
          turnLeaseGeneration: active.turnLeaseGeneration,
          leaseExpiresAt: active.leaseExpiresAt,
          abortRequested: active.abortRequested,
          abortReason: active.abortReason,
        };
        if (step.kind === "turn_complete") {
          next.terminalTurns.push({
            ...terminalTurnBase,
            status: "completed",
            result: structuredClone(step.result),
            error: null,
          });
        } else {
          next.terminalTurns.push({
            ...terminalTurnBase,
            status: "failed",
            result: null,
            error: structuredClone(step.error),
          });
        }
        next.latestSettledTurn = active.turnId;
        next.activeTurn = null;
        next.status = "ready";
      }
      outcome = {
        kind: "engine_step_committed",
        turnId: active.turnId,
        boundaryKind: step.kind,
        checkpointSequence: step.checkpoint.checkpointSequence,
        consumedEffectId,
        preparedEffectId,
        status,
      };
      break;
    }

    case "dispatch_effect": {
      const active = next.activeTurn;
      const effect = effectById(next, command.effectId);
      if (
        active === null ||
        active.activeEffectId !== command.effectId ||
        effect === undefined ||
        effect.turnId !== command.turnId
      ) {
        sessionError("NOT_FOUND", `effect ${command.effectId} is not active`);
      }
      if (active.abortRequested) {
        sessionError("ABORTED", "an aborted turn cannot issue a dispatch permit");
      }
      if (
        effect.invocationId !== command.invocationId ||
        effect.requestDigest !== command.requestDigest
      ) {
        sessionError("DIGEST_MISMATCH", "effect identity or requestDigest does not match");
      }
      if (effect.phase !== "prepared") {
        sessionError("FAILED_PRECONDITION", "only a prepared effect can be dispatched");
      }
      const transactionTime = validatedInteger(
        command.transactionTime,
        "transactionTime",
        0,
      );
      const deadline = validatedInteger(command.deadline, "deadline", 1);
      if (transactionTime >= deadline || deadline > active.leaseExpiresAt) {
        sessionError(
          "FAILED_PRECONDITION",
          "dispatch requires transactionTime < deadline <= leaseExpiresAt",
        );
      }
      effect.phase = "dispatched";
      effect.dispatchAttempt += 1;
      effect.lastDispatch = {
        dispatchAttempt: effect.dispatchAttempt,
        turnLeaseGeneration: active.turnLeaseGeneration,
        placementGeneration: next.placementGeneration,
        sandboxGeneration: next.sandboxGeneration,
        authorizationGeneration: next.authorizationGeneration,
        deadline,
        providerRequestId:
          command.providerRequestId === undefined || command.providerRequestId === null
            ? null
            : validatedIdentifier(command.providerRequestId, "providerRequestId"),
      };
      const dispatchPermitClaims = parseDispatchPermitClaims({
        tenantId: effect.tenantId,
        userId: effect.userId,
        sessionId: effect.sessionId,
        turnId: effect.turnId,
        effectId: effect.effectId,
        invocationId: effect.invocationId,
        requestDigest: effect.requestDigest,
        service: effect.service,
        operation: effect.operation,
        replayPolicy: effect.replayPolicy,
        ...(effect.parentOperationId === undefined
          ? {}
          : { parentOperationId: effect.parentOperationId, ordinal: effect.ordinal }),
        dispatchAttempt: effect.dispatchAttempt,
        turnLeaseGeneration: active.turnLeaseGeneration,
        placementGeneration: next.placementGeneration,
        sandboxGeneration: next.sandboxGeneration,
        authorizationGeneration: next.authorizationGeneration,
        deadline,
      });
      outcome = { kind: "effect_dispatched", effectId: effect.effectId, dispatchPermitClaims };
      break;
    }

    case "record_external_commit": {
      const active = next.activeTurn;
      const effect = effectById(next, command.effectId);
      if (
        active === null ||
        active.activeEffectId !== command.effectId ||
        effect === undefined ||
        effect.turnId !== command.turnId
      ) {
        sessionError("NOT_FOUND", `effect ${command.effectId} is not active`);
      }
      if (
        effect.invocationId !== command.invocationId ||
        effect.requestDigest !== command.requestDigest
      ) {
        sessionError("DIGEST_MISMATCH", "effect identity or requestDigest does not match");
      }
      const dispatchAttempt = validatedInteger(
        command.dispatchAttempt,
        "dispatchAttempt",
        1,
      );
      if (
        dispatchAttempt !== effect.dispatchAttempt ||
        effect.lastDispatch?.dispatchAttempt !== dispatchAttempt
      ) {
        sessionError("STALE_DISPATCH_ATTEMPT", "external commit used a stale dispatch attempt");
      }
      if (effect.phase !== "dispatched" && effect.phase !== "blocked") {
        sessionError(
          "FAILED_PRECONDITION",
          "external commit proof requires dispatched or blocked state",
        );
      }
      effect.externalCommitId = validatedIdentifier(
        command.externalCommitId,
        "externalCommitId",
      );
      effect.resultRef = validatedIdentifier(command.resultRef, "resultRef");
      effect.phase = "externally_committed";
      if (active.status === "needs_confirmation") {
        active.status = "active";
        next.status = "running";
      }
      outcome = {
        kind: "external_commit_recorded",
        effectId: effect.effectId,
        externalCommitId: effect.externalCommitId,
      };
      break;
    }

    case "settle_effect": {
      const active = next.activeTurn;
      const effect = effectById(next, command.effectId);
      if (
        active === null ||
        active.activeEffectId !== command.effectId ||
        effect === undefined ||
        effect.turnId !== command.turnId
      ) {
        sessionError("NOT_FOUND", `effect ${command.effectId} is not active`);
      }
      if (
        effect.invocationId !== command.invocationId ||
        effect.requestDigest !== command.requestDigest
      ) {
        sessionError("DIGEST_MISMATCH", "effect identity or requestDigest does not match");
      }
      if (effect.phase === "prepared") {
        if (command.dispatchAttempt !== null) {
          sessionError(
            "STALE_DISPATCH_ATTEMPT",
            "a pre-dispatch settlement cannot carry a dispatch attempt",
          );
        }
      } else {
        const dispatchAttempt = validatedInteger(
          command.dispatchAttempt,
          "dispatchAttempt",
          1,
        );
        if (
          dispatchAttempt !== effect.dispatchAttempt ||
          effect.lastDispatch?.dispatchAttempt !== dispatchAttempt
        ) {
          sessionError("STALE_DISPATCH_ATTEMPT", "settlement used a stale dispatch attempt");
        }
      }
      if (effect.phase === "settled" || effect.phase === "blocked") {
        sessionError("FAILED_PRECONDITION", `cannot settle an effect in ${effect.phase} state`);
      }
      if (command.settlement.kind === "abandoned") {
        sessionError(
          "FAILED_PRECONDITION",
          "abandonment requires an explicit confirmation resolution",
        );
      }
      if (effect.phase === "prepared" && command.settlement.kind === "success") {
        sessionError(
          "FAILED_PRECONDITION",
          "a prepared effect cannot succeed before a dispatch permit exists",
        );
      }
      let settlement: EffectSettlement;
      let settlementFields: readonly string[];
      switch (command.settlement.kind) {
        case "success":
          settlementFields = ["kind", "result"];
          break;
        case "error":
          settlementFields = ["kind", "code", "message", "retryable"];
          break;
        case "interrupted_unknown":
          settlementFields = ["kind", "reason"];
          break;
        default:
          sessionError("INVALID_ARGUMENT", "unknown settlement kind");
      }
      for (const key of Reflect.ownKeys(command.settlement)) {
        if (typeof key !== "string" || !settlementFields.includes(key)) {
          sessionError("INVALID_ARGUMENT", `unknown field ${String(key)} on settlement`);
        }
      }
      for (const field of settlementFields) {
        if (!Object.prototype.hasOwnProperty.call(command.settlement, field)) {
          sessionError("INVALID_ARGUMENT", `missing field ${field} on settlement`);
        }
      }
      switch (command.settlement.kind) {
        case "success":
          settlement = {
            kind: "success",
            result: normalizeProtocolValue(command.settlement.result),
          };
          break;
        case "error":
          settlement = {
            kind: "error",
            code: validatedIdentifier(command.settlement.code, "settlement.code"),
            message: validatedIdentifier(command.settlement.message, "settlement.message"),
            retryable: command.settlement.retryable,
          };
          if (typeof settlement.retryable !== "boolean") {
            sessionError("INVALID_ARGUMENT", "settlement.retryable must be a boolean");
          }
          break;
        case "interrupted_unknown":
          settlement = {
            kind: "interrupted_unknown",
            reason: validatedIdentifier(command.settlement.reason, "settlement.reason"),
          };
          break;
        default:
          sessionError("INVALID_ARGUMENT", "unknown settlement kind");
      }
      assertEffectSettlement(settlement, "settlement", "INVALID_ARGUMENT");
      effect.phase = "settled";
      effect.settlement = settlement;
      if (!active.abortRequested) {
        active.status = "active";
        next.status = "running";
      }
      outcome = { kind: "effect_settled", effectId: effect.effectId, settlement };
      break;
    }

    case "recover_effect": {
      const active = next.activeTurn;
      const effect = effectById(next, command.effectId);
      if (
        active === null ||
        active.activeEffectId !== command.effectId ||
        effect === undefined ||
        effect.turnId !== command.turnId
      ) {
        sessionError("NOT_FOUND", `effect ${command.effectId} is not active`);
      }
      if (
        effect.invocationId !== command.invocationId ||
        effect.requestDigest !== command.requestDigest
      ) {
        sessionError("DIGEST_MISMATCH", "effect identity or requestDigest does not match");
      }
      if (effect.phase !== "dispatched") {
        sessionError("FAILED_PRECONDITION", "only an uncertain dispatched effect is recoverable");
      }
      if (active.abortRequested) {
        if (effect.replayPolicy === "confirm") {
          effect.phase = "blocked";
          active.status = "needs_confirmation";
          outcome = { kind: "effect_recovered", effectId: effect.effectId, action: "blocked" };
        } else {
          effect.phase = "settled";
          effect.settlement = {
            kind: "interrupted_unknown",
            reason: "uncertain dispatch after abort is not replayed",
          };
          outcome = {
            kind: "effect_recovered",
            effectId: effect.effectId,
            action: "interrupted",
          };
        }
        break;
      }
      const transactionTime = validatedInteger(
        command.transactionTime,
        "transactionTime",
        0,
      );
      const deadline = validatedInteger(command.deadline, "deadline", 1);
      if (transactionTime >= deadline || deadline > active.leaseExpiresAt) {
        sessionError(
          "FAILED_PRECONDITION",
          "recovery requires transactionTime < deadline <= leaseExpiresAt",
        );
      }
      if (effect.replayPolicy === "safe" || effect.replayPolicy === "idempotency-key") {
        effect.dispatchAttempt += 1;
        effect.lastDispatch = {
          dispatchAttempt: effect.dispatchAttempt,
          turnLeaseGeneration: active.turnLeaseGeneration,
          placementGeneration: next.placementGeneration,
          sandboxGeneration: next.sandboxGeneration,
          authorizationGeneration: next.authorizationGeneration,
          deadline,
          providerRequestId:
            command.providerRequestId === undefined || command.providerRequestId === null
              ? null
              : validatedIdentifier(command.providerRequestId, "providerRequestId"),
        };
        const dispatchPermitClaims = parseDispatchPermitClaims({
          tenantId: effect.tenantId,
          userId: effect.userId,
          sessionId: effect.sessionId,
          turnId: effect.turnId,
          effectId: effect.effectId,
          invocationId: effect.invocationId,
          requestDigest: effect.requestDigest,
          service: effect.service,
          operation: effect.operation,
          replayPolicy: effect.replayPolicy,
          ...(effect.parentOperationId === undefined
            ? {}
            : { parentOperationId: effect.parentOperationId, ordinal: effect.ordinal }),
          dispatchAttempt: effect.dispatchAttempt,
          turnLeaseGeneration: active.turnLeaseGeneration,
          placementGeneration: next.placementGeneration,
          sandboxGeneration: next.sandboxGeneration,
          authorizationGeneration: next.authorizationGeneration,
          deadline,
        });
        outcome = {
          kind: "effect_recovered",
          effectId: effect.effectId,
          action: "retry",
          dispatchPermitClaims,
        };
      } else if (effect.replayPolicy === "never") {
        effect.phase = "settled";
        effect.settlement = {
          kind: "interrupted_unknown",
          reason: "uncertain dispatch is not replayable",
        };
        outcome = {
          kind: "effect_recovered",
          effectId: effect.effectId,
          action: "interrupted",
        };
      } else {
        effect.phase = "blocked";
        active.status = "needs_confirmation";
        outcome = { kind: "effect_recovered", effectId: effect.effectId, action: "blocked" };
      }
      break;
    }

    case "resolve_confirmation": {
      const active = next.activeTurn;
      const effect = effectById(next, command.effectId);
      if (
        active === null ||
        active.activeEffectId !== command.effectId ||
        effect === undefined ||
        effect.turnId !== command.turnId
      ) {
        sessionError("NOT_FOUND", `effect ${command.effectId} is not active`);
      }
      if (
        effect.invocationId !== command.invocationId ||
        effect.requestDigest !== command.requestDigest
      ) {
        sessionError("DIGEST_MISMATCH", "effect identity or requestDigest does not match");
      }
      if (effect.phase !== "blocked" || effect.replayPolicy !== "confirm") {
        sessionError("FAILED_PRECONDITION", "effect is not awaiting confirmation");
      }
      if (command.decision === "retry") {
        if (active.abortRequested) {
          sessionError("ABORTED", "an aborted turn cannot retry a confirmed effect");
        }
        const transactionTime = validatedInteger(
          command.transactionTime,
          "transactionTime",
          0,
        );
        const deadline = validatedInteger(command.deadline, "deadline", 1);
        if (transactionTime >= deadline || deadline > active.leaseExpiresAt) {
          sessionError(
            "FAILED_PRECONDITION",
            "confirmed retry requires transactionTime < deadline <= leaseExpiresAt",
          );
        }
        effect.phase = "dispatched";
        effect.dispatchAttempt += 1;
        active.status = "active";
        next.status = "running";
        effect.lastDispatch = {
          dispatchAttempt: effect.dispatchAttempt,
          turnLeaseGeneration: active.turnLeaseGeneration,
          placementGeneration: next.placementGeneration,
          sandboxGeneration: next.sandboxGeneration,
          authorizationGeneration: next.authorizationGeneration,
          deadline,
          providerRequestId:
            command.providerRequestId === undefined || command.providerRequestId === null
              ? null
              : validatedIdentifier(command.providerRequestId, "providerRequestId"),
        };
        const dispatchPermitClaims = parseDispatchPermitClaims({
          tenantId: effect.tenantId,
          userId: effect.userId,
          sessionId: effect.sessionId,
          turnId: effect.turnId,
          effectId: effect.effectId,
          invocationId: effect.invocationId,
          requestDigest: effect.requestDigest,
          service: effect.service,
          operation: effect.operation,
          replayPolicy: effect.replayPolicy,
          ...(effect.parentOperationId === undefined
            ? {}
            : { parentOperationId: effect.parentOperationId, ordinal: effect.ordinal }),
          dispatchAttempt: effect.dispatchAttempt,
          turnLeaseGeneration: active.turnLeaseGeneration,
          placementGeneration: next.placementGeneration,
          sandboxGeneration: next.sandboxGeneration,
          authorizationGeneration: next.authorizationGeneration,
          deadline,
        });
        outcome = {
          kind: "confirmation_resolved",
          effectId: effect.effectId,
          decision: "retry",
          dispatchPermitClaims,
        };
      } else if (command.decision === "abandon") {
        if (command.transactionTime !== null || command.deadline !== null) {
          sessionError(
            "INVALID_ARGUMENT",
            "abandon must not carry dispatch transaction time or deadline",
          );
        }
        effect.phase = "settled";
        effect.settlement = {
          kind: "abandoned",
          reason: "explicitly abandoned after confirmation",
        };
        active.status = "active";
        next.status = "running";
        outcome = {
          kind: "confirmation_resolved",
          effectId: effect.effectId,
          decision: "abandon",
        };
      } else {
        sessionError("INVALID_ARGUMENT", "unknown confirmation decision");
      }
      break;
    }

    case "request_abort": {
      const active = next.activeTurn;
      if (active === null || active.turnId !== command.turnId) {
        sessionError("NOT_FOUND", `turn ${command.turnId} is not active`);
      }
      const abortReason = validatedIdentifier(command.reason, "abort reason");
      const transactionTime = validatedInteger(command.transactionTime, "transactionTime", 0);
      active.abortRequested = true;
      active.abortReason = abortReason;
      if (active.activeEffectId === null) {
        const abortedTurnId = active.turnId;
        next.terminalTurns.push({
          turnId: active.turnId,
          sequence: active.sequence,
          input: structuredClone(active.input),
          inputDigest: active.inputDigest,
          finalCheckpoint: active.checkpoint,
          turnLeaseGeneration: active.turnLeaseGeneration,
          leaseExpiresAt: active.leaseExpiresAt,
          status: "aborted",
          abortRequested: true,
          abortReason,
          result: null,
          error: null,
        });
        next.latestSettledTurn = abortedTurnId;
        next.activeTurn = null;
        next.status = "ready";
        turnPromotionTime = transactionTime;
        outcome = { kind: "abort_requested", turnId: abortedTurnId, status: "aborted" };
      } else {
        outcome = {
          kind: "abort_requested",
          turnId: active.turnId,
          status: active.status,
        };
      }
      break;
    }

    case "finalize_abort": {
      const active = next.activeTurn;
      if (active === null || active.turnId !== command.turnId) {
        sessionError("NOT_FOUND", `turn ${command.turnId} is not active`);
      }
      if (!active.abortRequested) {
        sessionError("FAILED_PRECONDITION", "abort was not requested");
      }
      if (active.abortReason === null) {
        sessionError("FAILED_PRECONDITION", "abort reason is missing");
      }
      const transactionTime = validatedInteger(command.transactionTime, "transactionTime", 0);
      if (active.activeEffectId !== null) {
        const effect = effectById(next, active.activeEffectId);
        if (effect === undefined || effect.phase !== "settled") {
          sessionError("FAILED_PRECONDITION", "active effect is not safely settled");
        }
        if (effect.consumedAtCheckpointSequence !== null || effect.consumedByAbort) {
          sessionError("FAILED_PRECONDITION", "effect settlement was already consumed");
        }
        effect.consumedByAbort = true;
        active.activeEffectId = null;
      }
      const abortedTurnId = active.turnId;
      next.terminalTurns.push({
        turnId: active.turnId,
        sequence: active.sequence,
        input: structuredClone(active.input),
        inputDigest: active.inputDigest,
        finalCheckpoint: active.checkpoint,
        turnLeaseGeneration: active.turnLeaseGeneration,
        leaseExpiresAt: active.leaseExpiresAt,
        status: "aborted",
        abortRequested: true,
        abortReason: active.abortReason,
        result: null,
        error: null,
      });
      next.latestSettledTurn = abortedTurnId;
      next.activeTurn = null;
      next.status = "ready";
      turnPromotionTime = transactionTime;
      outcome = { kind: "abort_finalized", turnId: abortedTurnId, status: "aborted" };
      break;
    }

    case "rotate_turn_lease": {
      const active = next.activeTurn;
      if (active === null || active.turnId !== command.turnId) {
        sessionError("NOT_FOUND", `turn ${command.turnId} is not active`);
      }
      const transactionTime = validatedInteger(command.transactionTime, "transactionTime", 0);
      const nextTurnLeaseGeneration = validatedInteger(
        command.nextTurnLeaseGeneration,
        "nextTurnLeaseGeneration",
        1,
      );
      if (nextTurnLeaseGeneration !== active.turnLeaseGeneration + 1) {
        sessionError(
          "FAILED_PRECONDITION",
          "nextTurnLeaseGeneration must increment by exactly one",
        );
      }
      const nextLeaseExpiresAt = validatedInteger(
        command.nextLeaseExpiresAt,
        "nextLeaseExpiresAt",
        1,
      );
      if (nextLeaseExpiresAt <= transactionTime) {
        sessionError("FAILED_PRECONDITION", "the rotated turn lease must expire in the future");
      }
      active.turnLeaseGeneration = nextTurnLeaseGeneration;
      active.leaseExpiresAt = nextLeaseExpiresAt;
      outcome = {
        kind: "turn_lease_rotated",
        turnId: active.turnId,
        turnLeaseGeneration: nextTurnLeaseGeneration,
        leaseExpiresAt: nextLeaseExpiresAt,
      };
      break;
    }

    case "stage_runtime_revision": {
      const candidateRevision = parseDigest(
        command.candidateRevision,
        "candidateRevision",
      );
      if (next.runtimePointer.candidateRevision !== null) {
        sessionError("CONFLICT", "a runtime revision candidate is already staged");
      }
      if (
        candidateRevision === next.runtimePointer.activeRevision ||
        candidateRevision === next.runtimePointer.previousRevision
      ) {
        sessionError(
          "FAILED_PRECONDITION",
          "a runtime revision candidate must not alias an existing pointer",
        );
      }
      next.runtimePointer.candidateRevision = candidateRevision;
      outcome = {
        kind: "runtime_revision_staged",
        activeRevision: next.runtimePointer.activeRevision,
        candidateRevision,
        switchGeneration: next.runtimePointer.switchGeneration,
      };
      break;
    }

    case "discard_runtime_candidate": {
      const expectedCandidateRevision = parseDigest(
        command.expectedCandidateRevision,
        "expectedCandidateRevision",
      );
      const failureReceiptDigest = parseDigest(
        command.failureReceiptDigest,
        "failureReceiptDigest",
      );
      if (next.runtimePointer.candidateRevision !== expectedCandidateRevision) {
        sessionError("CONFLICT", "runtime revision candidate CAS failed");
      }
      next.runtimePointer.candidateRevision = null;
      outcome = {
        kind: "runtime_candidate_discarded",
        activeRevision: next.runtimePointer.activeRevision,
        candidateRevision: expectedCandidateRevision,
        switchGeneration: next.runtimePointer.switchGeneration,
        failureReceiptDigest,
      };
      break;
    }

    case "activate_runtime_revision": {
      const expectedActiveRevision = parseDigest(
        command.expectedActiveRevision,
        "expectedActiveRevision",
      );
      const expectedCandidateRevision = parseDigest(
        command.expectedCandidateRevision,
        "expectedCandidateRevision",
      );
      const expectedSwitchGeneration = validatedInteger(
        command.expectedSwitchGeneration,
        "expectedSwitchGeneration",
        1,
      );
      const healthReceiptDigest = parseDigest(
        command.healthReceiptDigest,
        "healthReceiptDigest",
      );
      const migrationReceiptDigest = parseDigest(
        command.migrationReceiptDigest,
        "migrationReceiptDigest",
      );
      if (
        next.runtimePointer.activeRevision !== expectedActiveRevision ||
        next.runtimePointer.candidateRevision !== expectedCandidateRevision ||
        next.runtimePointer.switchGeneration !== expectedSwitchGeneration
      ) {
        sessionError("CONFLICT", "runtime revision activation CAS failed");
      }
      if (next.activeTurn !== null || next.queuedTurns.length !== 0) {
        sessionError(
          "FAILED_PRECONDITION",
          "runtime revision activation requires all admitted turns to drain",
        );
      }
      if (next.runtimePointer.switchGeneration === Number.MAX_SAFE_INTEGER) {
        sessionError(
          "FAILED_PRECONDITION",
          "runtime revision switchGeneration cannot be incremented safely",
        );
      }
      const previousRevision = next.runtimePointer.activeRevision;
      next.runtimePointer.activeRevision = expectedCandidateRevision;
      next.runtimePointer.candidateRevision = null;
      next.runtimePointer.previousRevision = previousRevision;
      next.runtimePointer.switchGeneration += 1;
      next.runtimeRevisionDigest = expectedCandidateRevision;
      outcome = {
        kind: "runtime_revision_activated",
        activeRevision: expectedCandidateRevision,
        previousRevision,
        switchGeneration: next.runtimePointer.switchGeneration,
        healthReceiptDigest,
        migrationReceiptDigest,
      };
      break;
    }

    case "rollback_runtime_revision": {
      const expectedActiveRevision = parseDigest(
        command.expectedActiveRevision,
        "expectedActiveRevision",
      );
      const expectedPreviousRevision = parseDigest(
        command.expectedPreviousRevision,
        "expectedPreviousRevision",
      );
      const expectedSwitchGeneration = validatedInteger(
        command.expectedSwitchGeneration,
        "expectedSwitchGeneration",
        1,
      );
      const failureReceiptDigest = parseDigest(
        command.failureReceiptDigest,
        "failureReceiptDigest",
      );
      if (
        next.runtimePointer.activeRevision !== expectedActiveRevision ||
        next.runtimePointer.previousRevision !== expectedPreviousRevision ||
        next.runtimePointer.switchGeneration !== expectedSwitchGeneration
      ) {
        sessionError("CONFLICT", "runtime revision rollback CAS failed");
      }
      if (next.runtimePointer.candidateRevision !== null) {
        sessionError(
          "FAILED_PRECONDITION",
          "a staged runtime revision candidate must be discarded before rollback",
        );
      }
      if (next.activeTurn !== null || next.queuedTurns.length !== 0) {
        sessionError(
          "FAILED_PRECONDITION",
          "runtime revision rollback requires all admitted turns to drain",
        );
      }
      if (next.runtimePointer.switchGeneration === Number.MAX_SAFE_INTEGER) {
        sessionError(
          "FAILED_PRECONDITION",
          "runtime revision switchGeneration cannot be incremented safely",
        );
      }
      next.runtimePointer.activeRevision = expectedPreviousRevision;
      next.runtimePointer.previousRevision = expectedActiveRevision;
      next.runtimePointer.switchGeneration += 1;
      next.runtimeRevisionDigest = expectedPreviousRevision;
      outcome = {
        kind: "runtime_revision_rolled_back",
        activeRevision: expectedPreviousRevision,
        previousRevision: expectedActiveRevision,
        switchGeneration: next.runtimePointer.switchGeneration,
        failureReceiptDigest,
      };
      break;
    }

    case "rotate_generations": {
      const placementGeneration = validatedInteger(
        command.nextPlacementGeneration,
        "nextPlacementGeneration",
        next.placementGeneration,
      );
      const sandboxGeneration = validatedInteger(
        command.nextSandboxGeneration,
        "nextSandboxGeneration",
        next.sandboxGeneration,
      );
      const authorizationGeneration = validatedInteger(
        command.nextAuthorizationGeneration,
        "nextAuthorizationGeneration",
        next.authorizationGeneration,
      );
      const emergencyOverlayDigest = parseDigest(
        command.nextEmergencyOverlayDigest,
        "nextEmergencyOverlayDigest",
      );
      if (
        authorizationGeneration === next.authorizationGeneration &&
        emergencyOverlayDigest !== next.emergencyOverlayDigest
      ) {
        sessionError(
          "FAILED_PRECONDITION",
          "emergency overlay may change only with authorization generation",
        );
      }
      if (
        placementGeneration === next.placementGeneration &&
        sandboxGeneration === next.sandboxGeneration &&
        authorizationGeneration === next.authorizationGeneration
      ) {
        sessionError("FAILED_PRECONDITION", "at least one generation must increase");
      }
      next.placementGeneration = placementGeneration;
      next.sandboxGeneration = sandboxGeneration;
      next.authorizationGeneration = authorizationGeneration;
      next.emergencyOverlayDigest = emergencyOverlayDigest;
      outcome = {
        kind: "generations_rotated",
        placementGeneration,
        sandboxGeneration,
        authorizationGeneration,
        emergencyOverlayDigest,
      };
      break;
    }
  }

  if (turnPromotionTime !== null) {
    while (next.queuedTurns.length > 0) {
      const queued = next.queuedTurns.shift();
      if (queued === undefined) {
        sessionError("FAILED_PRECONDITION", "queued turn disappeared during promotion");
      }
      if (queued.leaseExpiresAt <= turnPromotionTime) {
        next.terminalTurns.push({
          turnId: queued.turnId,
          sequence: queued.sequence,
          input: structuredClone(queued.input),
          inputDigest: queued.inputDigest,
          finalCheckpoint: queued.checkpoint,
          turnLeaseGeneration: queued.turnLeaseGeneration,
          leaseExpiresAt: queued.leaseExpiresAt,
          status: "aborted",
          abortRequested: true,
          abortReason: "turn lease expired before activation",
          result: null,
          error: null,
        });
        next.latestSettledTurn = queued.turnId;
        continue;
      }
      next.activeTurn = {
        ...queued,
        status: "active",
        abortRequested: false,
        abortReason: null,
        activeEffectId: null,
      };
      next.status = "running";
      break;
    }
  }

  assertSessionCommandOutcome(outcome, "command outcome", "FAILED_PRECONDITION");
  next.eventSequence += 1;
  next.commandReceipts.push({
    commandId: command.commandId,
    commandDigest,
    committedEventSequence: next.eventSequence,
    outcome: structuredClone(outcome),
  });
  await validateSessionState(next);
  return { state: next, outcome, commandDigest, replayed: false };
}
