import { controlError } from "./errors.ts";
import {
  GENERATION_STATE_MAX_BYTES,
  assertEncodedSize,
  semanticCommandDigest,
  validatedAuthority,
  validatedDataRecord,
  validatedDigest,
  validatedExactFields,
  validatedIdentifier,
  validatedInteger,
} from "./validation.ts";
import {
  CONTROL_STATE_SCHEMA_VERSION,
  type ApplyCapabilityGenerationCommandResult,
  type CapabilityGenerationAggregateState,
  type CapabilityGenerationCommand,
  type CapabilityGenerationCommandOutcome,
  type CapabilityGenerationKind,
  type CapabilityGenerationRotation,
  type ControlAuthoritySnapshot,
  type ControlPermission,
  type ControlSubjectKind,
  type CreateCapabilityGenerationStateInput,
} from "./types.ts";

const GENERATION_STATE_FIELDS = [
  "schemaVersion",
  "tenantId",
  "subjectKind",
  "subjectId",
  "generationKind",
  "currentGeneration",
  "revokedThroughGeneration",
  "revision",
  "eventSequence",
  "history",
  "commandReceipts",
] as const;

function validatedCurrentGenerationAuthority(
  state: CapabilityGenerationAggregateState,
  authorityInput: ControlAuthoritySnapshot,
  now: number,
  permission: ControlPermission,
): ControlAuthoritySnapshot {
  const authority = validatedAuthority(
    authorityInput,
    {
      tenantId: state.tenantId,
      subjectKind: state.subjectKind,
      subjectId: state.subjectId,
    },
    now,
    permission,
  );
  if (
    state.generationKind === "authorization" &&
    authority.authorizationGeneration !== state.currentGeneration
  ) {
    controlError(
      "STALE_GENERATION",
      "authorization authority does not match the current authorization generation",
    );
  }
  return authority;
}

function validatedSubjectKind(value: unknown, field: string): ControlSubjectKind {
  if (
    value !== "tenant" &&
    value !== "user" &&
    value !== "workspace" &&
    value !== "session"
  ) {
    controlError("INVALID_ARGUMENT", `${field} is not a supported subject kind`);
  }
  return value;
}

function validatedGenerationKind(
  value: unknown,
  field: string,
): CapabilityGenerationKind {
  if (
    value !== "authorization" &&
    value !== "policy" &&
    value !== "placement" &&
    value !== "sandbox" &&
    value !== "workspace-security" &&
    value !== "credential"
  ) {
    controlError("INVALID_ARGUMENT", `${field} is not a supported generation kind`);
  }
  return value;
}

function assertGenerationState(state: CapabilityGenerationAggregateState): void {
  validatedExactFields(
    state,
    GENERATION_STATE_FIELDS,
    [],
    "state",
    "FAILED_PRECONDITION",
  );
  if (state.schemaVersion !== CONTROL_STATE_SCHEMA_VERSION) {
    controlError("FAILED_PRECONDITION", "state schemaVersion is unsupported");
  }
  validatedIdentifier(state.tenantId, "state.tenantId");
  validatedSubjectKind(state.subjectKind, "state.subjectKind");
  validatedIdentifier(state.subjectId, "state.subjectId");
  validatedGenerationKind(state.generationKind, "state.generationKind");
  validatedInteger(state.currentGeneration, "state.currentGeneration", 1);
  validatedInteger(
    state.revokedThroughGeneration,
    "state.revokedThroughGeneration",
    0,
  );
  if (state.revokedThroughGeneration !== state.currentGeneration - 1) {
    controlError(
      "FAILED_PRECONDITION",
      "revokedThroughGeneration must fence every generation before currentGeneration",
    );
  }
  validatedInteger(state.revision, "state.revision", 0);
  validatedInteger(state.eventSequence, "state.eventSequence", 0);
  if (
    state.revision !== state.eventSequence ||
    state.history.length !== state.eventSequence ||
    state.commandReceipts.length !== state.eventSequence
  ) {
    controlError(
      "FAILED_PRECONDITION",
      "generation revision, history, and receipt counts must agree",
    );
  }
  let expectedGeneration = state.currentGeneration - state.history.length + 1;
  let previousTimestamp = -1;
  for (const [index, candidate] of state.history.entries()) {
    const field = `state.history[${index}]`;
    const record = validatedExactFields(
      candidate,
      [
        "generation",
        "revokedThroughGeneration",
        "reason",
        "rotatedBy",
        "rotatedAt",
      ],
      [],
      field,
    );
    const generation = validatedInteger(record.generation, `${field}.generation`, 2);
    const revokedThroughGeneration = validatedInteger(
      record.revokedThroughGeneration,
      `${field}.revokedThroughGeneration`,
      1,
    );
    validatedIdentifier(record.reason, `${field}.reason`);
    validatedIdentifier(record.rotatedBy, `${field}.rotatedBy`);
    const rotatedAt = validatedInteger(record.rotatedAt, `${field}.rotatedAt`, 0);
    if (revokedThroughGeneration !== generation - 1) {
      controlError("FAILED_PRECONDITION", `${field} does not revoke the prior generation`);
    }
    if (generation !== expectedGeneration) {
      controlError("FAILED_PRECONDITION", "generation history is not contiguous");
    }
    if (rotatedAt < previousTimestamp) {
      controlError("FAILED_PRECONDITION", "generation rotation timestamps decreased");
    }
    expectedGeneration += 1;
    previousTimestamp = rotatedAt;
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
      controlError("FAILED_PRECONDITION", "generation receipt IDs must be unique");
    }
    commandIds.add(commandId);
    validatedDigest(receipt.commandDigest, `receipt[${index}].commandDigest`);
    if (receipt.committedSequence !== index + 1) {
      controlError("FAILED_PRECONDITION", "generation receipt sequence is not contiguous");
    }
    const outcomeField = `receipt[${index}].outcome`;
    const outcome = validatedExactFields(
      receipt.outcome,
      ["kind", "generation", "revokedThroughGeneration"],
      [],
      outcomeField,
    );
    if (outcome.kind !== "capability_generation_rotated") {
      controlError("FAILED_PRECONDITION", `${outcomeField}.kind is invalid`);
    }
    const generation = validatedInteger(
      outcome.generation,
      `${outcomeField}.generation`,
      2,
    );
    const revokedThrough = validatedInteger(
      outcome.revokedThroughGeneration,
      `${outcomeField}.revokedThroughGeneration`,
      1,
    );
    if (revokedThrough !== generation - 1) {
      controlError("FAILED_PRECONDITION", `${outcomeField} is not an exact rotation`);
    }
    if (receipt.outcome.generation !== state.history[index]?.generation) {
      controlError("FAILED_PRECONDITION", "generation receipt disagrees with history");
    }
  }
  assertEncodedSize(
    state,
    "state",
    GENERATION_STATE_MAX_BYTES,
    "FAILED_PRECONDITION",
  );
}

export function createCapabilityGenerationState(
  input: CreateCapabilityGenerationStateInput,
): CapabilityGenerationAggregateState {
  validatedExactFields(
    input,
    ["tenantId", "subjectKind", "subjectId", "generationKind", "initialGeneration"],
    [],
    "input",
  );
  const initialGeneration = validatedInteger(
    input.initialGeneration,
    "input.initialGeneration",
    1,
  );
  const state: CapabilityGenerationAggregateState = {
    schemaVersion: CONTROL_STATE_SCHEMA_VERSION,
    tenantId: validatedIdentifier(input.tenantId, "input.tenantId"),
    subjectKind: validatedSubjectKind(input.subjectKind, "input.subjectKind"),
    subjectId: validatedIdentifier(input.subjectId, "input.subjectId"),
    generationKind: validatedGenerationKind(
      input.generationKind,
      "input.generationKind",
    ),
    currentGeneration: initialGeneration,
    revokedThroughGeneration: initialGeneration - 1,
    revision: 0,
    eventSequence: 0,
    history: [],
    commandReceipts: [],
  };
  assertGenerationState(state);
  return state;
}

export function validateCapabilityGenerationState(
  state: CapabilityGenerationAggregateState,
): void {
  assertGenerationState(state);
}

export function assertCurrentCapabilityGeneration(
  state: CapabilityGenerationAggregateState,
  candidateGenerationInput: number,
  authorityInput: ControlAuthoritySnapshot,
  now: number,
): void {
  assertGenerationState(state);
  validatedCurrentGenerationAuthority(
    state,
    authorityInput,
    now,
    "generation.read",
  );
  const candidateGeneration = validatedInteger(
    candidateGenerationInput,
    "candidateGeneration",
    1,
  );
  if (candidateGeneration !== state.currentGeneration) {
    controlError(
      "STALE_GENERATION",
      `generation ${candidateGeneration} is not current ${state.currentGeneration}`,
    );
  }
}

export async function applyCapabilityGenerationCommand(
  state: CapabilityGenerationAggregateState,
  command: CapabilityGenerationCommand,
): Promise<ApplyCapabilityGenerationCommandResult> {
  assertGenerationState(state);
  const commandRecord = validatedDataRecord(command, "command");
  if (commandRecord.kind !== "rotate_capability_generation") {
    controlError("INVALID_ARGUMENT", "unknown CapabilityGeneration command kind");
  }
  validatedExactFields(
    command,
    [
      "kind",
      "commandId",
      "expectedRevision",
      "now",
      "authority",
      "nextGeneration",
      "reason",
    ],
    [],
    "command",
  );
  const commandId = validatedIdentifier(command.commandId, "command.commandId");
  const expectedRevision = validatedInteger(
    command.expectedRevision,
    "command.expectedRevision",
    0,
  );
  const now = validatedInteger(command.now, "command.now", 0);
  const authority = validatedCurrentGenerationAuthority(
    state,
    command.authority,
    now,
    "generation.rotate",
  );
  if (
    !authority.roles.includes("platform-admin") &&
    !authority.roles.includes("tenant-admin")
  ) {
    controlError(
      "PERMISSION_DENIED",
      "generation rotation requires a tenant or platform admin role",
    );
  }
  const nextGeneration = validatedInteger(
    command.nextGeneration,
    "command.nextGeneration",
    2,
  );
  const reason = validatedIdentifier(command.reason, "command.reason");
  const commandDigest = await semanticCommandDigest(
    "circulusd.state-app.capability-generation-command",
    {
      tenantId: state.tenantId,
      subjectKind: state.subjectKind,
      subjectId: state.subjectId,
      generationKind: state.generationKind,
      command: { kind: command.kind, commandId, expectedRevision, nextGeneration, reason },
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
  if (nextGeneration !== state.currentGeneration + 1) {
    controlError(
      "STALE_GENERATION",
      `nextGeneration must be exactly ${state.currentGeneration + 1}`,
    );
  }
  const lastRotation = state.history.at(-1);
  if (lastRotation !== undefined && now < lastRotation.rotatedAt) {
    controlError("FAILED_PRECONDITION", "rotation time cannot move backwards");
  }

  const next = structuredClone(state);
  next.currentGeneration = nextGeneration;
  next.revokedThroughGeneration = nextGeneration - 1;
  next.revision += 1;
  next.eventSequence += 1;
  const rotation: CapabilityGenerationRotation = {
    generation: nextGeneration,
    revokedThroughGeneration: nextGeneration - 1,
    reason,
    rotatedBy: authority.actorUserId,
    rotatedAt: now,
  };
  next.history.push(rotation);
  const outcome: CapabilityGenerationCommandOutcome = {
    kind: "capability_generation_rotated",
    generation: nextGeneration,
    revokedThroughGeneration: nextGeneration - 1,
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
    GENERATION_STATE_MAX_BYTES,
    "RESOURCE_EXHAUSTED",
  );
  assertGenerationState(next);
  return { state: next, outcome: structuredClone(outcome), commandDigest, replayed: false };
}
