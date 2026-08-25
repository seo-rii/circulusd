import type { Digest, NormalizedValue } from "@circulusd/protocol-types";

export const CONTROL_STATE_SCHEMA_VERSION = 1 as const;
export const CONTROL_COMMAND_SCHEMA_VERSION = 1 as const;

export type ControlRole =
  | "platform-admin"
  | "tenant-admin"
  | "workspace-owner"
  | "workspace-member"
  | "user";

export type ControlPermission =
  | "user.read"
  | "user.preferences.write"
  | "user.quota.write"
  | "extension-state.read"
  | "extension-state.write"
  | "generation.read"
  | "generation.rotate"
  | "audit.read"
  | "audit.append";

export type ControlSubjectKind = "tenant" | "user" | "workspace" | "session";

/**
 * A current ACL decision produced by the trusted state-plane adapter. Resource
 * identifiers supplied by an extension or client are comparison targets only.
 */
export interface ControlAuthoritySnapshot {
  readonly serviceBinding: "state";
  readonly tenantId: string;
  readonly actorUserId: string;
  readonly subjectKind: ControlSubjectKind;
  readonly subjectId: string;
  readonly roles: readonly ControlRole[];
  readonly permissions: readonly ControlPermission[];
  readonly authorizationGeneration: number;
  /** Current generation resolved by the trusted adapter for this invocation. */
  readonly currentAuthorizationGeneration: number;
  readonly issuedAt: number;
  readonly expiresAt: number;
}

export type ExecutionBackend = "nsjail" | "docker" | "firecracker";

export interface AgentIsolationPolicy {
  readonly processScope: "shared" | "tenant" | "session";
  readonly outerIsolation: "none" | "nsjail" | "docker" | "firecracker";
}

export interface ExtensionSelection {
  readonly id: string;
  readonly version: string;
}

export interface McpConfigurationRef {
  readonly id: string;
  readonly configuration: NormalizedValue;
}

export interface ControlCommandReceipt<Outcome> {
  commandId: string;
  commandDigest: Digest;
  committedSequence: number;
  outcome: Outcome;
}

export interface CreateUserStateInput {
  readonly userId: string;
  readonly tenantId: string;
  readonly defaultExtensions: readonly ExtensionSelection[];
  readonly defaultExecutionBackend: ExecutionBackend;
  readonly preferredAgentIsolation: AgentIsolationPolicy | null;
  readonly modelConfiguration: NormalizedValue;
  readonly mcpConfiguration: readonly McpConfigurationRef[];
  readonly quotaProfile: string;
}

export type UserCommandOutcome =
  | { readonly kind: "preferences_replaced"; readonly revision: number }
  | { readonly kind: "quota_profile_set"; readonly revision: number };

export interface UserAggregateState {
  schemaVersion: typeof CONTROL_STATE_SCHEMA_VERSION;
  userId: string;
  tenantId: string;
  defaultExtensions: ExtensionSelection[];
  defaultExecutionBackend: ExecutionBackend;
  preferredAgentIsolation: AgentIsolationPolicy | null;
  modelConfiguration: NormalizedValue;
  mcpConfiguration: McpConfigurationRef[];
  quotaProfile: string;
  revision: number;
  eventSequence: number;
  commandReceipts: ControlCommandReceipt<UserCommandOutcome>[];
}

interface UserCommandBase {
  readonly commandId: string;
  readonly expectedRevision: number;
  readonly now: number;
  readonly authority: ControlAuthoritySnapshot;
}

export interface ReplaceUserPreferencesCommand extends UserCommandBase {
  readonly kind: "replace_preferences";
  readonly defaultExtensions: readonly ExtensionSelection[];
  readonly defaultExecutionBackend: ExecutionBackend;
  readonly preferredAgentIsolation: AgentIsolationPolicy | null;
  readonly modelConfiguration: NormalizedValue;
  readonly mcpConfiguration: readonly McpConfigurationRef[];
}

export interface SetUserQuotaProfileCommand extends UserCommandBase {
  readonly kind: "set_quota_profile";
  readonly quotaProfile: string;
}

export type UserCommand = ReplaceUserPreferencesCommand | SetUserQuotaProfileCommand;

export interface ApplyUserCommandResult {
  readonly state: UserAggregateState;
  readonly outcome: UserCommandOutcome;
  readonly commandDigest: Digest;
  readonly replayed: boolean;
}

export type ExtensionScopeKind = "user" | "workspace" | "session";

export interface ExtensionStatePredecessor {
  readonly extensionSchemaVersion: number;
  readonly stateGeneration: number;
  readonly stateDigest: Digest;
}

export interface CreateExtensionStateInput {
  readonly tenantId: string;
  readonly scopeKind: ExtensionScopeKind;
  readonly scopeId: string;
  readonly extensionId: string;
  readonly extensionSchemaVersion: number;
  readonly stateGeneration: number;
  readonly predecessor: ExtensionStatePredecessor | null;
  readonly value: NormalizedValue;
}

export interface CreateMigratedExtensionStateInput {
  readonly extensionSchemaVersion: number;
  readonly value: NormalizedValue;
}

export type ExtensionStateCommandOutcome =
  | { readonly kind: "extension_state_replaced"; readonly revision: number }
  | { readonly kind: "extension_state_tombstoned"; readonly revision: number };

export interface ExtensionStateAggregateState {
  schemaVersion: typeof CONTROL_STATE_SCHEMA_VERSION;
  tenantId: string;
  scopeKind: ExtensionScopeKind;
  scopeId: string;
  extensionId: string;
  extensionSchemaVersion: number;
  stateGeneration: number;
  predecessor: ExtensionStatePredecessor | null;
  value: NormalizedValue;
  tombstoned: boolean;
  revision: number;
  eventSequence: number;
  commandReceipts: ControlCommandReceipt<ExtensionStateCommandOutcome>[];
}

interface ExtensionStateCommandBase {
  readonly commandId: string;
  readonly expectedRevision: number;
  readonly now: number;
  readonly authority: ControlAuthoritySnapshot;
}

export interface ReplaceExtensionStateCommand extends ExtensionStateCommandBase {
  readonly kind: "replace_extension_state";
  readonly value: NormalizedValue;
}

export interface TombstoneExtensionStateCommand extends ExtensionStateCommandBase {
  readonly kind: "tombstone_extension_state";
}

export type ExtensionStateCommand =
  | ReplaceExtensionStateCommand
  | TombstoneExtensionStateCommand;

export interface ApplyExtensionStateCommandResult {
  readonly state: ExtensionStateAggregateState;
  readonly outcome: ExtensionStateCommandOutcome;
  readonly commandDigest: Digest;
  readonly replayed: boolean;
}

export type CapabilityGenerationKind =
  | "authorization"
  | "policy"
  | "placement"
  | "sandbox"
  | "workspace-security"
  | "credential";

export interface CreateCapabilityGenerationStateInput {
  readonly tenantId: string;
  readonly subjectKind: ControlSubjectKind;
  readonly subjectId: string;
  readonly generationKind: CapabilityGenerationKind;
  readonly initialGeneration: number;
}

export interface CapabilityGenerationRotation {
  generation: number;
  revokedThroughGeneration: number;
  reason: string;
  rotatedBy: string;
  rotatedAt: number;
}

export type CapabilityGenerationCommandOutcome = {
  readonly kind: "capability_generation_rotated";
  readonly generation: number;
  readonly revokedThroughGeneration: number;
};

export interface CapabilityGenerationAggregateState {
  schemaVersion: typeof CONTROL_STATE_SCHEMA_VERSION;
  tenantId: string;
  subjectKind: ControlSubjectKind;
  subjectId: string;
  generationKind: CapabilityGenerationKind;
  currentGeneration: number;
  revokedThroughGeneration: number;
  revision: number;
  eventSequence: number;
  history: CapabilityGenerationRotation[];
  commandReceipts: ControlCommandReceipt<CapabilityGenerationCommandOutcome>[];
}

export interface RotateCapabilityGenerationCommand {
  readonly kind: "rotate_capability_generation";
  readonly commandId: string;
  readonly expectedRevision: number;
  readonly now: number;
  readonly authority: ControlAuthoritySnapshot;
  readonly nextGeneration: number;
  readonly reason: string;
}

export type CapabilityGenerationCommand = RotateCapabilityGenerationCommand;

export interface ApplyCapabilityGenerationCommandResult {
  readonly state: CapabilityGenerationAggregateState;
  readonly outcome: CapabilityGenerationCommandOutcome;
  readonly commandDigest: Digest;
  readonly replayed: boolean;
}

export interface AuditCorrelation {
  userId: string | null;
  sessionId: string | null;
  turnId: string | null;
  effectId: string | null;
  runtimeRevision: string | null;
  workspaceId: string | null;
  agentShardId: string | null;
  placementGeneration: number | null;
  executionBackend: ExecutionBackend | null;
  executionEnvironmentRevision: string | null;
  sandboxId: string | null;
  sandboxGeneration: number | null;
  invocationId: string | null;
}

export interface AuditEventInput {
  timestamp: number;
  actorUserId: string;
  eventType: string;
  result: "success" | "failure" | "denied" | "unknown";
  correlation: AuditCorrelation;
  metadata: NormalizedValue;
}

export interface AuditEntry {
  sequence: number;
  previousHash: Digest;
  hash: Digest;
  event: AuditEventInput;
}

export type AuditCommandOutcome = {
  readonly kind: "audit_event_appended";
  readonly sequence: number;
  readonly hash: Digest;
};

export interface AuditAggregateState {
  schemaVersion: typeof CONTROL_STATE_SCHEMA_VERSION;
  tenantId: string;
  sequence: number;
  headHash: Digest;
  entries: AuditEntry[];
  commandReceipts: ControlCommandReceipt<AuditCommandOutcome>[];
}

export interface CreateAuditStateInput {
  readonly tenantId: string;
}

export interface AppendAuditEventCommand {
  readonly kind: "append_audit_event";
  readonly commandId: string;
  readonly expectedSequence: number;
  readonly now: number;
  readonly authority: ControlAuthoritySnapshot;
  readonly event: AuditEventInput;
}

export type AuditCommand = AppendAuditEventCommand;

export interface ApplyAuditCommandResult {
  readonly state: AuditAggregateState;
  readonly outcome: AuditCommandOutcome;
  readonly commandDigest: Digest;
  readonly replayed: boolean;
}
