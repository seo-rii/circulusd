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
  type ControlCommandReceipt,
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

export interface AuditAppendHead {
  readonly tenantId: string;
  readonly sequence: number;
  readonly headHash: Digest;
  readonly previousTimestamp: number | null;
}

export interface PreparedAuditAppendCommand {
  readonly commandId: string;
  readonly expectedSequence: number;
  readonly event: AuditEventInput;
  readonly commandDigest: Digest;
}

export type AppliedAuditAppend =
  | {
      readonly replayed: true;
      readonly outcome: AuditCommandOutcome;
      readonly commandDigest: Digest;
    }
  | {
      readonly replayed: false;
      readonly entry: AuditEntry;
      readonly receipt: ControlCommandReceipt<AuditCommandOutcome>;
      readonly outcome: AuditCommandOutcome;
      readonly commandDigest: Digest;
    };

export async function validateAuditEntryReceipt(
  tenantId: string,
  expectedSequence: number,
  expectedPreviousHash: Digest,
  previousTimestamp: number | null,
  entry: AuditEntry,
  receipt: ControlCommandReceipt<AuditCommandOutcome>,
): Promise<void> {
  validatedExactFields(
    entry,
    ["sequence", "previousHash", "hash", "event"],
    [],
    `audit entry ${expectedSequence}`,
    "FAILED_PRECONDITION",
  );
  if (entry.sequence !== expectedSequence) {
    controlError("FAILED_PRECONDITION", "audit entry sequence is not contiguous");
  }
  validatedDigest(entry.previousHash, `audit entry ${expectedSequence}.previousHash`);
  validatedDigest(entry.hash, `audit entry ${expectedSequence}.hash`);
  if (entry.previousHash !== expectedPreviousHash) {
    controlError("FAILED_PRECONDITION", "audit previousHash chain is broken");
  }
  const event = validatedAuditEvent(
    entry.event,
    `audit entry ${expectedSequence}.event`,
    null,
  );
  if (previousTimestamp !== null && event.timestamp < previousTimestamp) {
    controlError("FAILED_PRECONDITION", "audit timestamps must not decrease");
  }

  validatedExactFields(
    receipt,
    ["commandId", "commandDigest", "committedSequence", "outcome"],
    [],
    `audit receipt ${expectedSequence}`,
    "FAILED_PRECONDITION",
  );
  const commandId = validatedIdentifier(
    receipt.commandId,
    `audit receipt ${expectedSequence}.commandId`,
  );
  const commandDigest = validatedDigest(
    receipt.commandDigest,
    `audit receipt ${expectedSequence}.commandDigest`,
  );
  if (receipt.committedSequence !== expectedSequence) {
    controlError("FAILED_PRECONDITION", "audit receipt sequence is not contiguous");
  }
  const outcome = validatedExactFields(
    receipt.outcome,
    ["kind", "sequence", "hash"],
    [],
    `audit receipt ${expectedSequence}.outcome`,
    "FAILED_PRECONDITION",
  );
  if (
    outcome.kind !== "audit_event_appended" ||
    outcome.sequence !== expectedSequence ||
    outcome.hash !== entry.hash
  ) {
    controlError("FAILED_PRECONDITION", "audit receipt disagrees with its entry");
  }
  validatedDigest(outcome.hash, `audit receipt ${expectedSequence}.outcome.hash`);

  const expectedHash = await auditEntryHash(
    tenantId,
    expectedSequence,
    expectedPreviousHash,
    commandId,
    commandDigest,
    event,
  );
  if (entry.hash !== expectedHash) {
    controlError(
      "FAILED_PRECONDITION",
      `audit entry ${expectedSequence} hash is invalid`,
    );
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
  let previousTimestamp: number | null = null;
  for (const [index, entry] of state.entries.entries()) {
    const receipt = state.commandReceipts[index];
    if (receipt === undefined) {
      controlError(
        "FAILED_PRECONDITION",
        `audit entry ${entry.sequence} has no authoritative command receipt`,
      );
    }
    await validateAuditEntryReceipt(
      state.tenantId,
      index + 1,
      expectedPreviousHash,
      previousTimestamp,
      entry,
      receipt,
    );
    expectedPreviousHash = entry.hash;
    previousTimestamp = entry.event.timestamp;
  }
  if (state.headHash !== expectedPreviousHash) {
    controlError("FAILED_PRECONDITION", "audit head hash is invalid");
  }
}

export function validateAuditReadRequest(
  tenantId: string,
  afterSequenceInput: number,
  limitInput: number,
  authority: ControlAuthoritySnapshot,
  now: number,
): { readonly afterSequence: number; readonly limit: number } {
  validatedAuthority(
    authority,
    { tenantId, subjectKind: "tenant", subjectId: tenantId },
    now,
    "audit.read",
  );
  const afterSequence = validatedInteger(afterSequenceInput, "afterSequence", 0);
  const limit = validatedInteger(limitInput, "limit", 1);
  if (limit > 1_000) {
    controlError("INVALID_ARGUMENT", "audit read limit cannot exceed 1000");
  }
  return { afterSequence, limit };
}

export async function readAuditEntries(
  state: AuditAggregateState,
  afterSequenceInput: number,
  limitInput: number,
  authority: ControlAuthoritySnapshot,
  now: number,
): Promise<AuditEntry[]> {
  await validateAuditState(state);
  const { afterSequence, limit } = validateAuditReadRequest(
    state.tenantId,
    afterSequenceInput,
    limitInput,
    authority,
    now,
  );
  return structuredClone(
    state.entries.filter((entry) => entry.sequence > afterSequence).slice(0, limit),
  );
}

export async function prepareAuditAppendCommand(
  tenantId: string,
  command: AuditCommand,
): Promise<PreparedAuditAppendCommand> {
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
    { tenantId, subjectKind: "tenant", subjectId: tenantId },
    now,
    "audit.append",
  );
  const event = validatedAuditEvent(command.event, "command.event", now);
  if (event.actorUserId !== authority.actorUserId) {
    controlError("PERMISSION_DENIED", "audit actor must match the authenticated actor");
  }
  const commandDigest = await semanticCommandDigest(
    "circulusd.state-app.audit-command",
    { tenantId, kind: command.kind, commandId, expectedSequence, event },
  );
  return { commandId, expectedSequence, event, commandDigest };
}

export async function applyPreparedAuditAppend(
  head: AuditAppendHead,
  command: PreparedAuditAppendCommand,
  existingReceipt: ControlCommandReceipt<AuditCommandOutcome> | undefined,
): Promise<AppliedAuditAppend> {
  if (existingReceipt !== undefined) {
    if (
      existingReceipt.commandId !== command.commandId ||
      existingReceipt.commandDigest !== command.commandDigest
    ) {
      controlError(
        "IDEMPOTENCY_CONFLICT",
        `commandId ${command.commandId} was reused with a different semantic digest`,
      );
    }
    return {
      outcome: structuredClone(existingReceipt.outcome),
      commandDigest: command.commandDigest,
      replayed: true,
    };
  }
  if (command.expectedSequence !== head.sequence) {
    controlError(
      "CONFLICT",
      `expected sequence ${command.expectedSequence}, current is ${head.sequence}`,
    );
  }
  if (
    head.previousTimestamp !== null &&
    command.event.timestamp < head.previousTimestamp
  ) {
    controlError("FAILED_PRECONDITION", "audit event timestamp cannot move backwards");
  }

  const sequence = head.sequence + 1;
  const hash = await auditEntryHash(
    head.tenantId,
    sequence,
    head.headHash,
    command.commandId,
    command.commandDigest,
    command.event,
  );
  const entry: AuditEntry = {
    sequence,
    previousHash: head.headHash,
    hash,
    event: command.event,
  };
  const outcome: AuditCommandOutcome = {
    kind: "audit_event_appended",
    sequence,
    hash,
  };
  return {
    entry,
    receipt: {
      commandId: command.commandId,
      commandDigest: command.commandDigest,
      committedSequence: sequence,
      outcome,
    },
    outcome,
    commandDigest: command.commandDigest,
    replayed: false,
  };
}

export async function applyAuditCommand(
  state: AuditAggregateState,
  command: AuditCommand,
): Promise<ApplyAuditCommandResult> {
  await validateAuditState(state);
  const prepared = await prepareAuditAppendCommand(state.tenantId, command);
  const receipt = state.commandReceipts.find(
    (candidate) => candidate.commandId === prepared.commandId,
  );
  const applied = await applyPreparedAuditAppend(
    {
      tenantId: state.tenantId,
      sequence: state.sequence,
      headHash: state.headHash,
      previousTimestamp: state.entries.at(-1)?.event.timestamp ?? null,
    },
    prepared,
    receipt,
  );
  if (applied.replayed) {
    return {
      state,
      outcome: applied.outcome,
      commandDigest: applied.commandDigest,
      replayed: true,
    };
  }
  const next = structuredClone(state);
  next.sequence = applied.entry.sequence;
  next.headHash = applied.entry.hash;
  next.entries.push(applied.entry);
  next.commandReceipts.push(applied.receipt);
  assertEncodedSize(next, "next state", AUDIT_STATE_MAX_BYTES, "RESOURCE_EXHAUSTED");
  await validateAuditState(next);
  return {
    state: next,
    outcome: structuredClone(applied.outcome),
    commandDigest: applied.commandDigest,
    replayed: false,
  };
}
