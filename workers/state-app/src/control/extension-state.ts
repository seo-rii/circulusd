import {
  ProtocolValidationError,
  digestStructuredValue,
  type Digest,
} from "@circulusd/protocol-types";

import { controlError } from "./errors.ts";
import {
  EXTENSION_STATE_MAX_BYTES,
  EXTENSION_VALUE_MAX_BYTES,
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
  type ApplyExtensionStateCommandResult,
  type CreateExtensionStateInput,
  type CreateMigratedExtensionStateInput,
  type ControlAuthoritySnapshot,
  type ExtensionScopeKind,
  type ExtensionStateAggregateState,
  type ExtensionStateCommand,
  type ExtensionStateCommandOutcome,
  type ExtensionStatePredecessor,
} from "./types.ts";

const EXTENSION_STATE_FIELDS = [
  "schemaVersion",
  "tenantId",
  "scopeKind",
  "scopeId",
  "extensionId",
  "extensionSchemaVersion",
  "stateGeneration",
  "predecessor",
  "value",
  "tombstoned",
  "revision",
  "eventSequence",
  "commandReceipts",
] as const;

function validatedScopeKind(value: unknown, field: string): ExtensionScopeKind {
  if (value !== "user" && value !== "workspace" && value !== "session") {
    controlError("INVALID_ARGUMENT", `${field} must be user, workspace, or session`);
  }
  return value;
}

function validatedPredecessor(
  value: unknown,
  extensionSchemaVersion: number,
  stateGeneration: number,
  field: string,
): ExtensionStatePredecessor | null {
  if (value === null) {
    if (stateGeneration !== 1) {
      controlError(
        "STALE_GENERATION",
        "only the initial stateGeneration may omit a predecessor",
      );
    }
    return null;
  }
  if (stateGeneration === 1) {
    controlError(
      "STALE_GENERATION",
      "the initial stateGeneration cannot have a predecessor",
    );
  }
  const record = validatedExactFields(
    value,
    ["extensionSchemaVersion", "stateGeneration", "stateDigest"],
    [],
    field,
  );
  const predecessorSchemaVersion = validatedInteger(
    record.extensionSchemaVersion,
    `${field}.extensionSchemaVersion`,
    1,
  );
  const predecessorStateGeneration = validatedInteger(
    record.stateGeneration,
    `${field}.stateGeneration`,
    1,
  );
  const stateDigest = validatedDigest(record.stateDigest, `${field}.stateDigest`);
  if (stateGeneration !== predecessorStateGeneration + 1) {
    controlError(
      "STALE_GENERATION",
      "copy-on-write stateGeneration must increment its predecessor by exactly one",
    );
  }
  if (extensionSchemaVersion < predecessorSchemaVersion) {
    controlError(
      "FAILED_PRECONDITION",
      "copy-on-write migration cannot decrease extensionSchemaVersion",
    );
  }
  return {
    extensionSchemaVersion: predecessorSchemaVersion,
    stateGeneration: predecessorStateGeneration,
    stateDigest,
  };
}

function assertExtensionState(state: ExtensionStateAggregateState): void {
  validatedExactFields(
    state,
    EXTENSION_STATE_FIELDS,
    [],
    "state",
    "FAILED_PRECONDITION",
  );
  if (state.schemaVersion !== CONTROL_STATE_SCHEMA_VERSION) {
    controlError("FAILED_PRECONDITION", "state schemaVersion is unsupported");
  }
  validatedIdentifier(state.tenantId, "state.tenantId");
  validatedScopeKind(state.scopeKind, "state.scopeKind");
  validatedIdentifier(state.scopeId, "state.scopeId");
  validatedIdentifier(state.extensionId, "state.extensionId");
  validatedInteger(
    state.extensionSchemaVersion,
    "state.extensionSchemaVersion",
    1,
  );
  validatedInteger(state.stateGeneration, "state.stateGeneration", 1);
  validatedPredecessor(
    state.predecessor,
    state.extensionSchemaVersion,
    state.stateGeneration,
    "state.predecessor",
  );
  validatedBoundedValue(state.value, "state.value", EXTENSION_VALUE_MAX_BYTES);
  if (typeof state.tombstoned !== "boolean") {
    controlError("FAILED_PRECONDITION", "state.tombstoned must be a boolean");
  }
  if (state.tombstoned && state.value !== null) {
    controlError("FAILED_PRECONDITION", "a tombstoned extension state must have null value");
  }
  validatedInteger(state.revision, "state.revision", 0);
  validatedInteger(state.eventSequence, "state.eventSequence", 0);
  if (
    state.revision !== state.eventSequence ||
    state.commandReceipts.length !== state.eventSequence
  ) {
    controlError(
      "FAILED_PRECONDITION",
      "extension revision, eventSequence, and receipt count must agree",
    );
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
      controlError("FAILED_PRECONDITION", "extension receipt IDs must be unique");
    }
    commandIds.add(commandId);
    validatedDigest(receipt.commandDigest, `receipt[${index}].commandDigest`);
    if (receipt.committedSequence !== index + 1) {
      controlError("FAILED_PRECONDITION", "extension receipt sequence is not contiguous");
    }
    const outcome = validatedExactFields(
      receipt.outcome,
      ["kind", "revision"],
      [],
      `receipt[${index}].outcome`,
    );
    if (
      outcome.kind !== "extension_state_replaced" &&
      outcome.kind !== "extension_state_tombstoned"
    ) {
      controlError("FAILED_PRECONDITION", `receipt[${index}].outcome.kind is invalid`);
    }
    validatedInteger(outcome.revision, `receipt[${index}].outcome.revision`, 1);
    if (receipt.outcome.revision !== receipt.committedSequence) {
      controlError("FAILED_PRECONDITION", "extension receipt revision is inconsistent");
    }
  }
  assertEncodedSize(
    state,
    "state",
    EXTENSION_STATE_MAX_BYTES,
    "FAILED_PRECONDITION",
  );
}

export function createExtensionState(
  input: CreateExtensionStateInput,
): ExtensionStateAggregateState {
  validatedExactFields(
    input,
    [
      "tenantId",
      "scopeKind",
      "scopeId",
      "extensionId",
      "extensionSchemaVersion",
      "stateGeneration",
      "predecessor",
      "value",
    ],
    [],
    "input",
  );
  const extensionSchemaVersion = validatedInteger(
    input.extensionSchemaVersion,
    "input.extensionSchemaVersion",
    1,
  );
  const stateGeneration = validatedInteger(
    input.stateGeneration,
    "input.stateGeneration",
    1,
  );
  const state: ExtensionStateAggregateState = {
    schemaVersion: CONTROL_STATE_SCHEMA_VERSION,
    tenantId: validatedIdentifier(input.tenantId, "input.tenantId"),
    scopeKind: validatedScopeKind(input.scopeKind, "input.scopeKind"),
    scopeId: validatedIdentifier(input.scopeId, "input.scopeId"),
    extensionId: validatedIdentifier(input.extensionId, "input.extensionId"),
    extensionSchemaVersion,
    stateGeneration,
    predecessor: validatedPredecessor(
      input.predecessor,
      extensionSchemaVersion,
      stateGeneration,
      "input.predecessor",
    ),
    value: validatedBoundedValue(
      input.value,
      "input.value",
      EXTENSION_VALUE_MAX_BYTES,
    ),
    tombstoned: false,
    revision: 0,
    eventSequence: 0,
    commandReceipts: [],
  };
  assertEncodedSize(
    state,
    "state",
    EXTENSION_STATE_MAX_BYTES,
    "RESOURCE_EXHAUSTED",
  );
  return state;
}

export function extensionStateKey(
  state: Pick<
    ExtensionStateAggregateState,
    | "tenantId"
    | "scopeKind"
    | "scopeId"
    | "extensionId"
    | "extensionSchemaVersion"
    | "stateGeneration"
  >,
): string {
  return [
    state.tenantId,
    state.scopeKind,
    state.scopeId,
    state.extensionId,
    String(state.extensionSchemaVersion),
    String(state.stateGeneration),
  ]
    .map((part) => encodeURIComponent(part))
    .join("/");
}

export async function extensionStateDigest(
  state: ExtensionStateAggregateState,
): Promise<Digest> {
  assertExtensionState(state);
  try {
    return await digestStructuredValue("circulusd.extension-state", 1, {
      key: extensionStateKey(state),
      predecessor: state.predecessor,
      revision: state.revision,
      tombstoned: state.tombstoned,
      value: state.value,
    });
  } catch (error) {
    if (error instanceof ProtocolValidationError) {
      controlError("FAILED_PRECONDITION", `extension state cannot be hashed: ${error.message}`);
    }
    throw error;
  }
}

export async function createMigratedExtensionState(
  source: ExtensionStateAggregateState,
  input: CreateMigratedExtensionStateInput,
): Promise<ExtensionStateAggregateState> {
  assertExtensionState(source);
  const sourceSnapshot = structuredClone(source);
  validatedExactFields(input, ["extensionSchemaVersion", "value"], [], "input");
  const extensionSchemaVersion = validatedInteger(
    input.extensionSchemaVersion,
    "input.extensionSchemaVersion",
    1,
  );
  const value = validatedBoundedValue(
    input.value,
    "input.value",
    EXTENSION_VALUE_MAX_BYTES,
  );
  if (sourceSnapshot.tombstoned) {
    controlError("FAILED_PRECONDITION", "a tombstoned extension state cannot be migrated");
  }
  if (!Number.isSafeInteger(sourceSnapshot.stateGeneration + 1)) {
    controlError("STALE_GENERATION", "stateGeneration cannot be incremented safely");
  }
  const predecessorDigest = await extensionStateDigest(sourceSnapshot);
  return createExtensionState({
    tenantId: sourceSnapshot.tenantId,
    scopeKind: sourceSnapshot.scopeKind,
    scopeId: sourceSnapshot.scopeId,
    extensionId: sourceSnapshot.extensionId,
    extensionSchemaVersion,
    stateGeneration: sourceSnapshot.stateGeneration + 1,
    predecessor: {
      extensionSchemaVersion: sourceSnapshot.extensionSchemaVersion,
      stateGeneration: sourceSnapshot.stateGeneration,
      stateDigest: predecessorDigest,
    },
    value,
  });
}

export async function validateExtensionState(
  state: ExtensionStateAggregateState,
): Promise<void> {
  assertExtensionState(state);
}

export async function readExtensionState(
  state: ExtensionStateAggregateState,
  authority: ControlAuthoritySnapshot,
  now: number,
): Promise<ExtensionStateAggregateState> {
  assertExtensionState(state);
  validatedAuthority(
    authority,
    {
      tenantId: state.tenantId,
      subjectKind: state.scopeKind,
      subjectId: state.scopeId,
    },
    now,
    "extension-state.read",
  );
  return structuredClone(state);
}

export async function applyExtensionStateCommand(
  state: ExtensionStateAggregateState,
  command: ExtensionStateCommand,
): Promise<ApplyExtensionStateCommandResult> {
  assertExtensionState(state);
  const commandRecord = validatedDataRecord(command, "command");
  let fields: readonly string[];
  switch (commandRecord.kind) {
    case "replace_extension_state":
      fields = [
        "kind",
        "commandId",
        "expectedRevision",
        "now",
        "authority",
        "value",
      ];
      break;
    case "tombstone_extension_state":
      fields = ["kind", "commandId", "expectedRevision", "now", "authority"];
      break;
    default:
      controlError("INVALID_ARGUMENT", "unknown ExtensionState command kind");
  }
  validatedExactFields(command, fields, [], "command");
  const commandId = validatedIdentifier(command.commandId, "command.commandId");
  const expectedRevision = validatedInteger(
    command.expectedRevision,
    "command.expectedRevision",
    0,
  );
  validatedAuthority(
    command.authority,
    {
      tenantId: state.tenantId,
      subjectKind: state.scopeKind,
      subjectId: state.scopeId,
    },
    command.now,
    "extension-state.write",
  );
  const value =
    command.kind === "replace_extension_state"
      ? validatedBoundedValue(
          command.value,
          "command.value",
          EXTENSION_VALUE_MAX_BYTES,
        )
      : null;
  const commandDigest = await semanticCommandDigest(
    "circulusd.state-app.extension-state-command",
    {
      extensionStateKey: extensionStateKey(state),
      kind: command.kind,
      commandId,
      expectedRevision,
      ...(command.kind === "replace_extension_state" ? { value } : {}),
    },
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
  if (expectedRevision !== state.revision) {
    controlError(
      "CONFLICT",
      `expected revision ${expectedRevision}, current is ${state.revision}`,
    );
  }

  const next = structuredClone(state);
  next.revision += 1;
  next.eventSequence += 1;
  next.value = value;
  next.tombstoned = command.kind === "tombstone_extension_state";
  const outcome: ExtensionStateCommandOutcome = {
    kind:
      command.kind === "replace_extension_state"
        ? "extension_state_replaced"
        : "extension_state_tombstoned",
    revision: next.revision,
  };
  next.commandReceipts.push({
    commandId,
    commandDigest,
    committedSequence: next.eventSequence,
    outcome,
  });
  assertEncodedSize(
    next,
    "next state",
    EXTENSION_STATE_MAX_BYTES,
    "RESOURCE_EXHAUSTED",
  );
  assertExtensionState(next);
  return { state: next, outcome: structuredClone(outcome), commandDigest, replayed: false };
}
