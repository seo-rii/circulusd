import type { NormalizedValue } from "@circulusd/protocol-types";

import { controlError } from "./errors.ts";
import {
  USER_STATE_MAX_BYTES,
  USER_VALUE_MAX_BYTES,
  assertEncodedSize,
  compareUtf8,
  semanticCommandDigest,
  validatedAuthority,
  validatedBoundedValue,
  validatedDataArray,
  validatedDataRecord,
  validatedDigest,
  validatedExactFields,
  validatedIdentifier,
  validatedInteger,
} from "./validation.ts";
import {
  CONTROL_STATE_SCHEMA_VERSION,
  type AgentIsolationPolicy,
  type ApplyUserCommandResult,
  type CreateUserStateInput,
  type ControlAuthoritySnapshot,
  type ExecutionBackend,
  type ExtensionSelection,
  type McpConfigurationRef,
  type UserAggregateState,
  type UserCommand,
  type UserCommandOutcome,
} from "./types.ts";

const USER_STATE_FIELDS = [
  "schemaVersion",
  "userId",
  "tenantId",
  "defaultExtensions",
  "defaultExecutionBackend",
  "preferredAgentIsolation",
  "modelConfiguration",
  "mcpConfiguration",
  "quotaProfile",
  "revision",
  "eventSequence",
  "commandReceipts",
] as const;

function validatedBackend(value: unknown, field: string): ExecutionBackend {
  if (value !== "nsjail" && value !== "docker" && value !== "firecracker") {
    controlError("INVALID_ARGUMENT", `${field} must name a supported execution backend`);
  }
  return value;
}

function validatedIsolation(
  value: unknown,
  field: string,
): AgentIsolationPolicy | null {
  if (value === null) {
    return null;
  }
  const record = validatedExactFields(
    value,
    ["processScope", "outerIsolation"],
    [],
    field,
  );
  if (
    record.processScope !== "shared" &&
    record.processScope !== "tenant" &&
    record.processScope !== "session"
  ) {
    controlError("INVALID_ARGUMENT", `${field}.processScope is invalid`);
  }
  if (
    record.outerIsolation !== "none" &&
    record.outerIsolation !== "nsjail" &&
    record.outerIsolation !== "docker" &&
    record.outerIsolation !== "firecracker"
  ) {
    controlError("INVALID_ARGUMENT", `${field}.outerIsolation is invalid`);
  }
  return {
    processScope: record.processScope,
    outerIsolation: record.outerIsolation,
  };
}

function validatedExtensions(
  value: unknown,
  field: string,
): ExtensionSelection[] {
  const candidates = validatedDataArray(value, field);
  const result: ExtensionSelection[] = [];
  let previousId: string | null = null;
  for (const [index, candidate] of candidates.entries()) {
    const record = validatedExactFields(
      candidate,
      ["id", "version"],
      [],
      `${field}[${index}]`,
    );
    const id = validatedIdentifier(record.id, `${field}[${index}].id`);
    const version = validatedIdentifier(record.version, `${field}[${index}].version`);
    if (previousId !== null && compareUtf8(id, previousId) <= 0) {
      controlError("INVALID_ARGUMENT", `${field} must be sorted by unique extension id`);
    }
    previousId = id;
    result.push({ id, version });
  }
  return result;
}

function validatedMcpConfiguration(
  value: unknown,
  field: string,
): McpConfigurationRef[] {
  const candidates = validatedDataArray(value, field);
  const result: McpConfigurationRef[] = [];
  let previousId: string | null = null;
  for (const [index, candidate] of candidates.entries()) {
    const record = validatedExactFields(
      candidate,
      ["id", "configuration"],
      [],
      `${field}[${index}]`,
    );
    const id = validatedIdentifier(record.id, `${field}[${index}].id`);
    if (previousId !== null && compareUtf8(id, previousId) <= 0) {
      controlError("INVALID_ARGUMENT", `${field} must be sorted by unique MCP id`);
    }
    previousId = id;
    result.push({
      id,
      configuration: validatedBoundedValue(
        record.configuration,
        `${field}[${index}].configuration`,
        USER_VALUE_MAX_BYTES,
      ),
    });
  }
  return result;
}

function assertUserState(state: UserAggregateState): void {
  validatedExactFields(state, USER_STATE_FIELDS, [], "state", "FAILED_PRECONDITION");
  if (state.schemaVersion !== CONTROL_STATE_SCHEMA_VERSION) {
    controlError("FAILED_PRECONDITION", "state schemaVersion is unsupported");
  }
  validatedIdentifier(state.userId, "state.userId");
  validatedIdentifier(state.tenantId, "state.tenantId");
  validatedExtensions(state.defaultExtensions, "state.defaultExtensions");
  validatedBackend(state.defaultExecutionBackend, "state.defaultExecutionBackend");
  validatedIsolation(state.preferredAgentIsolation, "state.preferredAgentIsolation");
  validatedBoundedValue(
    state.modelConfiguration,
    "state.modelConfiguration",
    USER_VALUE_MAX_BYTES,
  );
  validatedMcpConfiguration(state.mcpConfiguration, "state.mcpConfiguration");
  validatedIdentifier(state.quotaProfile, "state.quotaProfile");
  validatedInteger(state.revision, "state.revision", 0);
  validatedInteger(state.eventSequence, "state.eventSequence", 0);
  if (
    state.revision !== state.eventSequence ||
    state.commandReceipts.length !== state.eventSequence
  ) {
    controlError(
      "FAILED_PRECONDITION",
      "user revision, eventSequence, and receipt count must agree",
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
      controlError("FAILED_PRECONDITION", "user command receipt IDs must be unique");
    }
    commandIds.add(commandId);
    validatedDigest(receipt.commandDigest, `receipt[${index}].commandDigest`);
    if (receipt.committedSequence !== index + 1) {
      controlError("FAILED_PRECONDITION", "user receipt sequence is not contiguous");
    }
    const outcome = validatedExactFields(
      receipt.outcome,
      ["kind", "revision"],
      [],
      `receipt[${index}].outcome`,
    );
    if (
      outcome.kind !== "preferences_replaced" &&
      outcome.kind !== "quota_profile_set"
    ) {
      controlError("FAILED_PRECONDITION", `receipt[${index}].outcome.kind is invalid`);
    }
    validatedInteger(outcome.revision, `receipt[${index}].outcome.revision`, 1);
    if (receipt.outcome.revision !== receipt.committedSequence) {
      controlError("FAILED_PRECONDITION", "user receipt outcome revision is inconsistent");
    }
  }
  assertEncodedSize(
    state,
    "state",
    USER_STATE_MAX_BYTES,
    "FAILED_PRECONDITION",
  );
}

export function createUserState(input: CreateUserStateInput): UserAggregateState {
  validatedExactFields(
    input,
    [
      "userId",
      "tenantId",
      "defaultExtensions",
      "defaultExecutionBackend",
      "preferredAgentIsolation",
      "modelConfiguration",
      "mcpConfiguration",
      "quotaProfile",
    ],
    [],
    "input",
  );
  const state: UserAggregateState = {
    schemaVersion: CONTROL_STATE_SCHEMA_VERSION,
    userId: validatedIdentifier(input.userId, "input.userId"),
    tenantId: validatedIdentifier(input.tenantId, "input.tenantId"),
    defaultExtensions: validatedExtensions(
      input.defaultExtensions,
      "input.defaultExtensions",
    ),
    defaultExecutionBackend: validatedBackend(
      input.defaultExecutionBackend,
      "input.defaultExecutionBackend",
    ),
    preferredAgentIsolation: validatedIsolation(
      input.preferredAgentIsolation,
      "input.preferredAgentIsolation",
    ),
    modelConfiguration: validatedBoundedValue(
      input.modelConfiguration,
      "input.modelConfiguration",
      USER_VALUE_MAX_BYTES,
    ),
    mcpConfiguration: validatedMcpConfiguration(
      input.mcpConfiguration,
      "input.mcpConfiguration",
    ),
    quotaProfile: validatedIdentifier(input.quotaProfile, "input.quotaProfile"),
    revision: 0,
    eventSequence: 0,
    commandReceipts: [],
  };
  assertEncodedSize(state, "state", USER_STATE_MAX_BYTES, "RESOURCE_EXHAUSTED");
  return state;
}

export async function validateUserState(state: UserAggregateState): Promise<void> {
  assertUserState(state);
}

export async function readUserState(
  state: UserAggregateState,
  authority: ControlAuthoritySnapshot,
  now: number,
): Promise<UserAggregateState> {
  assertUserState(state);
  validatedAuthority(
    authority,
    { tenantId: state.tenantId, subjectKind: "user", subjectId: state.userId },
    now,
    "user.read",
  );
  return structuredClone(state);
}

export async function applyUserCommand(
  state: UserAggregateState,
  command: UserCommand,
): Promise<ApplyUserCommandResult> {
  assertUserState(state);
  const commandRecord = validatedDataRecord(command, "command");
  let fields: readonly string[];
  let requiredPermission: "user.preferences.write" | "user.quota.write";
  switch (commandRecord.kind) {
    case "replace_preferences":
      fields = [
        "kind",
        "commandId",
        "expectedRevision",
        "now",
        "authority",
        "defaultExtensions",
        "defaultExecutionBackend",
        "preferredAgentIsolation",
        "modelConfiguration",
        "mcpConfiguration",
      ];
      requiredPermission = "user.preferences.write";
      break;
    case "set_quota_profile":
      fields = [
        "kind",
        "commandId",
        "expectedRevision",
        "now",
        "authority",
        "quotaProfile",
      ];
      requiredPermission = "user.quota.write";
      break;
    default:
      controlError("INVALID_ARGUMENT", "unknown user command kind");
  }
  validatedExactFields(command, fields, [], "command");
  const commandId = validatedIdentifier(command.commandId, "command.commandId");
  const expectedRevision = validatedInteger(
    command.expectedRevision,
    "command.expectedRevision",
    0,
  );
  const authority = validatedAuthority(
    command.authority,
    { tenantId: state.tenantId, subjectKind: "user", subjectId: state.userId },
    command.now,
    requiredPermission,
  );
  if (
    command.kind === "set_quota_profile" &&
    !authority.roles.includes("platform-admin") &&
    !authority.roles.includes("tenant-admin")
  ) {
    controlError("PERMISSION_DENIED", "quota changes require a tenant or platform admin");
  }

  let semantic: Record<string, unknown>;
  let preferences:
    | {
        readonly defaultExtensions: ExtensionSelection[];
        readonly defaultExecutionBackend: ExecutionBackend;
        readonly preferredAgentIsolation: AgentIsolationPolicy | null;
        readonly modelConfiguration: NormalizedValue;
        readonly mcpConfiguration: McpConfigurationRef[];
      }
    | undefined;
  let quotaProfile: string | undefined;
  if (command.kind === "replace_preferences") {
    preferences = {
      defaultExtensions: validatedExtensions(
        command.defaultExtensions,
        "command.defaultExtensions",
      ),
      defaultExecutionBackend: validatedBackend(
        command.defaultExecutionBackend,
        "command.defaultExecutionBackend",
      ),
      preferredAgentIsolation: validatedIsolation(
        command.preferredAgentIsolation,
        "command.preferredAgentIsolation",
      ),
      modelConfiguration: validatedBoundedValue(
        command.modelConfiguration,
        "command.modelConfiguration",
        USER_VALUE_MAX_BYTES,
      ),
      mcpConfiguration: validatedMcpConfiguration(
        command.mcpConfiguration,
        "command.mcpConfiguration",
      ),
    };
    semantic = {
      kind: command.kind,
      commandId,
      expectedRevision,
      ...preferences,
    };
  } else {
    quotaProfile = validatedIdentifier(command.quotaProfile, "command.quotaProfile");
    semantic = {
      kind: command.kind,
      commandId,
      expectedRevision,
      quotaProfile,
    };
  }
  const commandDigest = await semanticCommandDigest(
    "circulusd.state-app.user-command",
    { tenantId: state.tenantId, userId: state.userId, command: semantic },
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
  let outcome: UserCommandOutcome;
  next.revision += 1;
  next.eventSequence += 1;
  if (command.kind === "replace_preferences") {
    if (preferences === undefined) {
      controlError("FAILED_PRECONDITION", "validated preferences are unavailable");
    }
    next.defaultExtensions = preferences.defaultExtensions;
    next.defaultExecutionBackend = preferences.defaultExecutionBackend;
    next.preferredAgentIsolation = preferences.preferredAgentIsolation;
    next.modelConfiguration = preferences.modelConfiguration;
    next.mcpConfiguration = preferences.mcpConfiguration;
    outcome = { kind: "preferences_replaced", revision: next.revision };
  } else {
    if (quotaProfile === undefined) {
      controlError("FAILED_PRECONDITION", "validated quota profile is unavailable");
    }
    next.quotaProfile = quotaProfile;
    outcome = { kind: "quota_profile_set", revision: next.revision };
  }
  next.commandReceipts.push({
    commandId,
    commandDigest,
    committedSequence: next.eventSequence,
    outcome,
  });
  assertEncodedSize(next, "next state", USER_STATE_MAX_BYTES, "RESOURCE_EXHAUSTED");
  assertUserState(next);
  return { state: next, outcome: structuredClone(outcome), commandDigest, replayed: false };
}
