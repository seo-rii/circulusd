import {
  ProtocolValidationError,
  digestStructuredValue,
  type Digest,
} from "@circulusd/protocol-types";

import { controlError } from "./errors.ts";
import {
  AUDIT_EVENT_MAX_BYTES,
  AUDIT_STATE_MAX_BYTES,
  assertEncodedSize,
  semanticCommandDigest,
  validatedAuthority,
  validatedBoundedValue,
  validatedDataRecord,
  validatedDigest,
  validatedExactFields,
  validatedIdentifier,
  validatedInteger,
} from "./validation.ts";
import {
  CONTROL_STATE_SCHEMA_VERSION,
  type ApplyAuditCommandResult,
  type AuditAggregateState,
  type AuditCommand,
  type AuditCommandOutcome,
  type AuditEntry,
  type AuditEventInput,
  type ControlAuthoritySnapshot,
  type CreateAuditStateInput,
} from "./types.ts";

export const AUDIT_GENESIS_HASH = `sha256:${"0".repeat(64)}` as Digest;

const AUDIT_STATE_FIELDS = [
  "schemaVersion",
  "tenantId",
  "sequence",
  "headHash",
  "entries",
  "commandReceipts",
] as const;

const AUDIT_EVENT_FIELDS = [
  "timestamp",
  "actorUserId",
  "eventType",
  "result",
  "correlation",
  "metadata",
] as const;

const AUDIT_CORRELATION_FIELDS = [
  "userId",
  "sessionId",
  "turnId",
  "effectId",
  "runtimeRevision",
  "workspaceId",
  "agentShardId",
  "placementGeneration",
  "executionBackend",
  "executionEnvironmentRevision",
  "sandboxId",
  "sandboxGeneration",
  "invocationId",
] as const;

function validatedAuditEvent(
  value: unknown,
  field: string,
  maximumTimestamp: number | null,
): AuditEventInput {
  const record = validatedExactFields(value, AUDIT_EVENT_FIELDS, [], field);
  const timestamp = validatedInteger(record.timestamp, `${field}.timestamp`, 0);
  if (maximumTimestamp !== null && timestamp > maximumTimestamp) {
    controlError("FAILED_PRECONDITION", "audit event timestamp is in the future");
  }
  const result = record.result;
  if (
    result !== "success" &&
    result !== "failure" &&
    result !== "denied" &&
    result !== "unknown"
  ) {
    controlError("INVALID_ARGUMENT", `${field}.result is invalid`);
  }
  const metadata = validatedBoundedValue(
    record.metadata,
    `${field}.metadata`,
    AUDIT_EVENT_MAX_BYTES,
  );
  const pendingMetadata = [metadata];
  const forbiddenMetadataField =
    /(secret|authority|capability|prompt|response|filecontent|stdin|stdout)/iu;
  while (pendingMetadata.length > 0) {
    const current = pendingMetadata.pop();
    if (current === undefined || current === null || typeof current !== "object") {
      continue;
    }
    if (current instanceof Uint8Array) {
      continue;
    }
    if (Array.isArray(current)) {
      pendingMetadata.push(...current);
      continue;
    }
    for (const [key, entry] of Object.entries(current)) {
      if (forbiddenMetadataField.test(key.replace(/[_.-]/gu, ""))) {
        controlError("INVALID_ARGUMENT", `audit metadata field ${key} is forbidden`);
      }
      pendingMetadata.push(entry);
    }
  }
  const correlationField = `${field}.correlation`;
  const correlation = validatedExactFields(
    record.correlation,
    AUDIT_CORRELATION_FIELDS,
    [],
    correlationField,
  );
  const executionBackend = correlation.executionBackend;
  if (
    executionBackend !== null &&
    executionBackend !== "nsjail" &&
    executionBackend !== "docker" &&
    executionBackend !== "firecracker"
  ) {
    controlError(
      "INVALID_ARGUMENT",
      `${correlationField}.executionBackend is not a supported backend`,
    );
  }
  const event: AuditEventInput = {
    timestamp,
    actorUserId: validatedIdentifier(record.actorUserId, `${field}.actorUserId`),
    eventType: validatedIdentifier(record.eventType, `${field}.eventType`),
    result,
    correlation: {
      userId:
        correlation.userId === null
          ? null
          : validatedIdentifier(correlation.userId, `${correlationField}.userId`),
      sessionId:
        correlation.sessionId === null
          ? null
          : validatedIdentifier(correlation.sessionId, `${correlationField}.sessionId`),
      turnId:
        correlation.turnId === null
          ? null
          : validatedIdentifier(correlation.turnId, `${correlationField}.turnId`),
      effectId:
        correlation.effectId === null
          ? null
          : validatedIdentifier(correlation.effectId, `${correlationField}.effectId`),
      runtimeRevision:
        correlation.runtimeRevision === null
          ? null
          : validatedIdentifier(
              correlation.runtimeRevision,
              `${correlationField}.runtimeRevision`,
            ),
      workspaceId:
        correlation.workspaceId === null
          ? null
          : validatedIdentifier(correlation.workspaceId, `${correlationField}.workspaceId`),
      agentShardId:
        correlation.agentShardId === null
          ? null
          : validatedIdentifier(correlation.agentShardId, `${correlationField}.agentShardId`),
      placementGeneration:
        correlation.placementGeneration === null
          ? null
          : validatedInteger(
              correlation.placementGeneration,
              `${correlationField}.placementGeneration`,
              1,
            ),
      executionBackend,
      executionEnvironmentRevision:
        correlation.executionEnvironmentRevision === null
          ? null
          : validatedIdentifier(
              correlation.executionEnvironmentRevision,
              `${correlationField}.executionEnvironmentRevision`,
            ),
      sandboxId:
        correlation.sandboxId === null
          ? null
          : validatedIdentifier(correlation.sandboxId, `${correlationField}.sandboxId`),
      sandboxGeneration:
        correlation.sandboxGeneration === null
          ? null
          : validatedInteger(
              correlation.sandboxGeneration,
              `${correlationField}.sandboxGeneration`,
              1,
            ),
      invocationId:
        correlation.invocationId === null
          ? null
          : validatedIdentifier(correlation.invocationId, `${correlationField}.invocationId`),
    },
    metadata,
  };
  assertEncodedSize(event, field, AUDIT_EVENT_MAX_BYTES, "RESOURCE_EXHAUSTED");
  return event;
}

async function auditEntryHash(
  tenantId: string,
  sequence: number,
  previousHash: Digest,
  commandId: string,
  commandDigest: Digest,
  event: AuditEventInput,
): Promise<Digest> {
  try {
    return await digestStructuredValue("circulusd.audit-entry", 1, {
      tenantId,
      sequence,
      previousHash,
      commandId,
      commandDigest,
      event,
    });
  } catch (error) {
    if (error instanceof ProtocolValidationError) {
      controlError("INVALID_ARGUMENT", `audit entry cannot be hashed: ${error.message}`);
    }
    throw error;
  }
}

function assertAuditStateShape(state: AuditAggregateState): void {
  validatedExactFields(
    state,
    AUDIT_STATE_FIELDS,
    [],
    "state",
    "FAILED_PRECONDITION",
  );
  if (state.schemaVersion !== CONTROL_STATE_SCHEMA_VERSION) {
    controlError("FAILED_PRECONDITION", "state schemaVersion is unsupported");
  }
  validatedIdentifier(state.tenantId, "state.tenantId");
  validatedInteger(state.sequence, "state.sequence", 0);
  validatedDigest(state.headHash, "state.headHash");
  if (!Array.isArray(state.entries) || !Array.isArray(state.commandReceipts)) {
    controlError("FAILED_PRECONDITION", "audit entries and receipts must be arrays");
  }
  if (
    state.entries.length !== state.sequence ||
    state.commandReceipts.length !== state.sequence
  ) {
    controlError("FAILED_PRECONDITION", "audit sequence, entries, and receipts must agree");
  }
  let expectedPreviousHash = AUDIT_GENESIS_HASH;
  let previousTimestamp = -1;
  for (const [index, entry] of state.entries.entries()) {
    validatedExactFields(
      entry,
      ["sequence", "previousHash", "hash", "event"],
      [],
      `state.entries[${index}]`,
      "FAILED_PRECONDITION",
    );
    if (entry.sequence !== index + 1) {
      controlError("FAILED_PRECONDITION", "audit entry sequence is not contiguous");
    }
    validatedDigest(entry.previousHash, `state.entries[${index}].previousHash`);
    validatedDigest(entry.hash, `state.entries[${index}].hash`);
    if (entry.previousHash !== expectedPreviousHash) {
      controlError("FAILED_PRECONDITION", "audit previousHash chain is broken");
    }
    const validatedEvent = validatedAuditEvent(
      entry.event,
      `state.entries[${index}].event`,
      null,
    );
    if (validatedEvent.timestamp < previousTimestamp) {
      controlError("FAILED_PRECONDITION", "audit timestamps must not decrease");
    }
    previousTimestamp = validatedEvent.timestamp;
    expectedPreviousHash = entry.hash;
  }
  const expectedHead = state.entries.at(-1)?.hash ?? AUDIT_GENESIS_HASH;
  if (state.headHash !== expectedHead) {
    controlError("FAILED_PRECONDITION", "audit headHash does not match the chain head");
  }
  const commandIds = new Set<string>();
  for (const [index, receipt] of state.commandReceipts.entries()) {
    validatedExactFields(
      receipt,
      ["commandId", "commandDigest", "committedSequence", "outcome"],
      [],
      `state.commandReceipts[${index}]`,
      "FAILED_PRECONDITION",
    );
    const commandId = validatedIdentifier(receipt.commandId, `receipt[${index}].commandId`);
    if (commandIds.has(commandId)) {
      controlError("FAILED_PRECONDITION", "audit receipt IDs must be unique");
    }
    commandIds.add(commandId);
    validatedDigest(receipt.commandDigest, `receipt[${index}].commandDigest`);
    if (receipt.committedSequence !== index + 1) {
      controlError("FAILED_PRECONDITION", "audit receipt sequence is not contiguous");
    }
    const outcomeField = `receipt[${index}].outcome`;
    const outcome = validatedExactFields(
      receipt.outcome,
      ["kind", "sequence", "hash"],
      [],
      outcomeField,
    );
    if (outcome.kind !== "audit_event_appended") {
      controlError("FAILED_PRECONDITION", `${outcomeField}.kind is invalid`);
    }
    validatedInteger(outcome.sequence, `${outcomeField}.sequence`, 1);
    validatedDigest(outcome.hash, `${outcomeField}.hash`);
    const entry = state.entries[index];
    if (
      entry === undefined ||
      receipt.outcome.sequence !== entry.sequence ||
      receipt.outcome.hash !== entry.hash
    ) {
      controlError("FAILED_PRECONDITION", "audit receipt disagrees with its entry");
    }
  }
  assertEncodedSize(state, "state", AUDIT_STATE_MAX_BYTES, "FAILED_PRECONDITION");
}

export function createAuditState(input: CreateAuditStateInput): AuditAggregateState {
  validatedExactFields(input, ["tenantId"], [], "input");
  const state: AuditAggregateState = {
    schemaVersion: CONTROL_STATE_SCHEMA_VERSION,
    tenantId: validatedIdentifier(input.tenantId, "input.tenantId"),
    sequence: 0,
    headHash: AUDIT_GENESIS_HASH,
    entries: [],
    commandReceipts: [],
  };
  assertAuditStateShape(state);
  return state;
}

export async function validateAuditState(state: AuditAggregateState): Promise<void> {
  assertAuditStateShape(state);
  let expectedPreviousHash = AUDIT_GENESIS_HASH;
  for (const [index, entry] of state.entries.entries()) {
    const receipt = state.commandReceipts[index];
    if (receipt === undefined) {
      controlError(
        "FAILED_PRECONDITION",
        `audit entry ${entry.sequence} has no authoritative command receipt`,
      );
    }
    const expectedHash = await auditEntryHash(
      state.tenantId,
      entry.sequence,
      expectedPreviousHash,
      receipt.commandId,
      receipt.commandDigest,
      entry.event,
    );
    if (entry.hash !== expectedHash) {
      controlError("FAILED_PRECONDITION", `audit entry ${entry.sequence} hash is invalid`);
    }
    expectedPreviousHash = expectedHash;
  }
  if (state.headHash !== expectedPreviousHash) {
    controlError("FAILED_PRECONDITION", "audit head hash is invalid");
  }
}

export async function readAuditEntries(
  state: AuditAggregateState,
  afterSequenceInput: number,
  limitInput: number,
  authority: ControlAuthoritySnapshot,
  now: number,
): Promise<AuditEntry[]> {
  await validateAuditState(state);
  validatedAuthority(
    authority,
    { tenantId: state.tenantId, subjectKind: "tenant", subjectId: state.tenantId },
    now,
    "audit.read",
  );
  const afterSequence = validatedInteger(afterSequenceInput, "afterSequence", 0);
  const limit = validatedInteger(limitInput, "limit", 1);
  if (limit > 1_000) {
    controlError("INVALID_ARGUMENT", "audit read limit cannot exceed 1000");
  }
  return structuredClone(
    state.entries.filter((entry) => entry.sequence > afterSequence).slice(0, limit),
  );
}

export async function applyAuditCommand(
  state: AuditAggregateState,
  command: AuditCommand,
): Promise<ApplyAuditCommandResult> {
  await validateAuditState(state);
  const commandRecord = validatedDataRecord(command, "command");
  if (commandRecord.kind !== "append_audit_event") {
    controlError("INVALID_ARGUMENT", "unknown Audit command kind");
  }
  validatedExactFields(
    command,
    ["kind", "commandId", "expectedSequence", "now", "authority", "event"],
    [],
    "command",
  );
  const commandId = validatedIdentifier(command.commandId, "command.commandId");
  const expectedSequence = validatedInteger(
    command.expectedSequence,
    "command.expectedSequence",
    0,
  );
  const now = validatedInteger(command.now, "command.now", 0);
  const authority = validatedAuthority(
    command.authority,
    { tenantId: state.tenantId, subjectKind: "tenant", subjectId: state.tenantId },
    now,
    "audit.append",
  );
  const event = validatedAuditEvent(command.event, "command.event", now);
  if (event.actorUserId !== authority.actorUserId) {
    controlError("PERMISSION_DENIED", "audit actor must match the authenticated actor");
  }
  const commandDigest = await semanticCommandDigest(
    "circulusd.state-app.audit-command",
    { tenantId: state.tenantId, kind: command.kind, commandId, expectedSequence, event },
  );
  const receipt = state.commandReceipts.find(
    (candidate) => candidate.commandId === commandId,
  );
  if (receipt !== undefined) {
    if (receipt.commandDigest !== commandDigest) {
      controlError(
        "IDEMPOTENCY_CONFLICT",
        `commandId ${commandId} was reused with a different semantic digest`,
      );
    }
    return {
      state,
      outcome: structuredClone(receipt.outcome),
      commandDigest,
      replayed: true,
    };
  }
  if (expectedSequence !== state.sequence) {
    controlError(
      "CONFLICT",
      `expected sequence ${expectedSequence}, current is ${state.sequence}`,
    );
  }
  const previousTimestamp = state.entries.at(-1)?.event.timestamp;
  if (previousTimestamp !== undefined && event.timestamp < previousTimestamp) {
    controlError("FAILED_PRECONDITION", "audit event timestamp cannot move backwards");
  }

  const sequence = state.sequence + 1;
  const hash = await auditEntryHash(
    state.tenantId,
    sequence,
    state.headHash,
    commandId,
    commandDigest,
    event,
  );
  const entry: AuditEntry = {
    sequence,
    previousHash: state.headHash,
    hash,
    event,
  };
  const outcome: AuditCommandOutcome = {
    kind: "audit_event_appended",
    sequence,
    hash,
  };
  const next = structuredClone(state);
  next.sequence = sequence;
  next.headHash = hash;
  next.entries.push(entry);
  next.commandReceipts.push({
    commandId,
    commandDigest,
    committedSequence: sequence,
    outcome,
  });
  assertEncodedSize(next, "next state", AUDIT_STATE_MAX_BYTES, "RESOURCE_EXHAUSTED");
  await validateAuditState(next);
  return { state: next, outcome: structuredClone(outcome), commandDigest, replayed: false };
}
