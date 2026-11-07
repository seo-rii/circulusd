import { DurableObject } from "cloudflare:workers";

import { parseDigest, parseNormalizedValue, type Digest } from "@circulusd/protocol-types";

import {
  applySessionCommand,
  createSessionState,
  migrateSessionState,
  readSessionPayload,
  replaySessionPublicEvents,
  validateSessionState,
  type CreateSessionStateInput,
  type SessionAggregateState,
  type SessionCommand,
  type SessionCommandOutcome,
  type StoredSessionCommandOutcome,
  type SessionPublicEventReplay,
  type SessionApplyContext,
  type ApplySessionCommandResult,
} from "../session/index.ts";
import {
  applyWorkspaceCommand,
  assertWorkspaceInvariants,
  createWorkspaceState,
  lookupWorkspaceInvocation,
  type CreateWorkspaceStateInput,
  type WorkspaceAggregateState,
  type WorkspaceAuthoritySnapshot,
  type WorkspaceCommand,
  type WorkspaceCommandOutcome,
  type WorkspaceInvocationRecord,
} from "../workspace/index.ts";
import {
  applyCapabilityGenerationCommand,
  applyExtensionStateCommand,
  applyUserCommand,
  assertCurrentCapabilityGeneration,
  controlError,
  createCapabilityGenerationState,
  createExtensionState,
  createUserState,
  readExtensionState,
  readUserState,
  validateCapabilityGenerationState,
  validateExtensionState,
  validateUserState,
  type AuditCommand,
  type AuditCommandOutcome,
  type AuditEntry,
  type CapabilityGenerationAggregateState,
  type CapabilityGenerationCommand,
  type CapabilityGenerationCommandOutcome,
  type ControlAuthoritySnapshot,
  type CreateAuditStateInput,
  type CreateCapabilityGenerationStateInput,
  type CreateExtensionStateInput,
  type CreateUserStateInput,
  type ExtensionStateAggregateState,
  type ExtensionStateCommand,
  type ExtensionStateCommandOutcome,
  type UserAggregateState,
  type UserCommand,
  type UserCommandOutcome,
} from "../control/index.ts";
import { validatedAuthority } from "../control/validation.ts";
import {
  HostContractError,
  type AggregateAdapter,
  type CellRoutePort,
  type CommittedCommandResult,
  type DurableObjectNamespacePort,
  type DurableObjectStatePort,
  type InitializationResult,
} from "./contracts.ts";
import { AuditCellKernel } from "./audit-kernel.ts";
import { TransactionalAggregateKernel } from "./kernel.ts";
import { SessionHistoryStore, sessionHistoryCompanion } from "./session-history-store.ts";
import { brokerCommand, brokerLookupKey, parseTypedBrokerPayload, sessionBrokerHostPolicy } from "./broker.ts";
import { assertSessionAdmissionPlanningAuthority, parseSessionAdmissionPlanningRequest, planSessionAdmission,
  sessionAdmissionHostPolicy, validateSessionAdmissionPlanningDigests } from "./admission.ts";
import { assertSessionBrokerAuthority, materializeSessionBrokerReceipt, readSessionBrokerTurn, sessionBrokerLookupResult,
  sessionError, type SessionBrokerPolicy, type SessionBrokerOperationReceipt, type SessionBrokerReceiptValue, type SessionBrokerTurn } from "../session/index.ts";
import {
  capabilityGenerationCellName,
  extensionStateCellName,
  sessionCellName,
  userCellName,
  workspaceCellName,
} from "./names.ts";
import { CELLD_HOST_PROFILE } from "./profiles.ts";
import {
  invokeHostRpc,
  type HostRpcResponse,
} from "./rpc.ts";

const sessionAdapter: AggregateAdapter<
  SessionAggregateState,
  CreateSessionStateInput,
  SessionCommand,
  StoredSessionCommandOutcome,
  SessionCommandOutcome,
  SessionApplyContext,
  ApplySessionCommandResult
> = {
  kind: "session",
  cellName: (initialization) =>
    sessionCellName(initialization.tenantId, initialization.sessionId),
  create: createSessionState,
  migrate: migrateSessionState,
  validate: validateSessionState,
  apply: (state, command, context) => applySessionCommand(state, command, context),
  materializeOutcome: async (outcome, { readBlob }) => {
    if (outcome.kind === "broker_result") return { kind: "broker_result", result: await materializeSessionBrokerReceipt(outcome.receipt, readBlob, outcome.replayedClaim) };
    if (outcome.kind !== "effect_settled") return outcome;
    const settlement = outcome.settlement;
    if (settlement.kind !== "success") return { ...outcome, settlement };
    if (settlement.resultPayloadRef === undefined) {
      return { ...outcome, settlement: { kind: "success", result: settlement.result } };
    }
    return {
      ...outcome,
      settlement: {
        kind: "success",
        result: await readSessionPayload(settlement.resultPayloadRef, readBlob),
      },
    };
  },
  version: (state) => state.eventSequence,
};

const workspaceAdapter: AggregateAdapter<
  WorkspaceAggregateState,
  CreateWorkspaceStateInput,
  WorkspaceCommand,
  WorkspaceCommandOutcome
> = {
  kind: "workspace",
  cellName: (initialization) =>
    workspaceCellName(initialization.tenantId, initialization.workspaceId),
  create: createWorkspaceState,
  validate: assertWorkspaceInvariants,
  apply: applyWorkspaceCommand,
  version: (state) => state.eventSequence,
};

const userAdapter: AggregateAdapter<
  UserAggregateState,
  CreateUserStateInput,
  UserCommand,
  UserCommandOutcome
> = {
  kind: "user",
  cellName: (initialization) =>
    userCellName(initialization.tenantId, initialization.userId),
  create: createUserState,
  validate: validateUserState,
  apply: applyUserCommand,
  version: (state) => state.revision,
};

const extensionStateAdapter: AggregateAdapter<
  ExtensionStateAggregateState,
  CreateExtensionStateInput,
  ExtensionStateCommand,
  ExtensionStateCommandOutcome
> = {
  kind: "extension-state",
  cellName: extensionStateCellName,
  create: createExtensionState,
  validate: validateExtensionState,
  apply: applyExtensionStateCommand,
  version: (state) => state.revision,
};

const capabilityGenerationAdapter: AggregateAdapter<
  CapabilityGenerationAggregateState,
  CreateCapabilityGenerationStateInput,
  CapabilityGenerationCommand,
  CapabilityGenerationCommandOutcome
> = {
  kind: "capability-generation",
  cellName: capabilityGenerationCellName,
  create: createCapabilityGenerationState,
  validate: validateCapabilityGenerationState,
  apply: applyCapabilityGenerationCommand,
  version: (state) => state.revision,
};

type StateBindingName =
  | "SESSION_CELL"
  | "WORKSPACE_CELL"
  | "USER_CELL"
  | "EXTENSION_STATE_CELL"
  | "CAPABILITY_GENERATION_CELL"
  | "AUDIT_CELL";

interface StateHostEnvironment {
  readonly CIRCULUSD_STATE_ADMISSION_POLICY?: unknown;
  readonly CIRCULUSD_STATE_BROKER_POLICY?: unknown;
  readonly SESSION_CELL: DurableObjectNamespacePort;
  readonly WORKSPACE_CELL: DurableObjectNamespacePort;
  readonly USER_CELL: DurableObjectNamespacePort;
  readonly EXTENSION_STATE_CELL: DurableObjectNamespacePort;
  readonly CAPABILITY_GENERATION_CELL: DurableObjectNamespacePort;
  readonly AUDIT_CELL: DurableObjectNamespacePort;
}

type StateHostContext = DurableObjectState & DurableObjectStatePort;

function cellRoute(
  state: DurableObjectStatePort,
  environment: unknown,
  bindingName: StateBindingName,
): CellRoutePort {
  if (
    typeof state !== "object" ||
    state === null ||
    typeof (state as { readonly storage?: { readonly transaction?: unknown } }).storage !==
      "object" ||
    typeof (state as { readonly storage?: { readonly transaction?: unknown } }).storage
      ?.transaction !== "function"
  ) {
    throw new HostContractError(
      "STORAGE_CONTRACT",
      "Durable Object state must provide transactional storage",
    );
  }
  const currentId = state.id;
  if (
    typeof currentId !== "object" ||
    currentId === null ||
    typeof currentId.equals !== "function" ||
    typeof currentId.toString !== "function" ||
    typeof environment !== "object" ||
    environment === null
  ) {
    throw new HostContractError(
      "CELL_ID_MISMATCH",
      "Durable Object state and environment must provide a physical route",
    );
  }
  const namespace = (environment as Partial<Record<StateBindingName, unknown>>)[
    bindingName
  ];
  if (
    typeof namespace !== "object" ||
    namespace === null ||
    typeof (namespace as { readonly idFromName?: unknown }).idFromName !== "function"
  ) {
    throw new HostContractError(
      "CELL_ID_MISMATCH",
      `Durable Object environment is missing ${bindingName}`,
    );
  }
  return {
    currentId,
    namespace: namespace as DurableObjectNamespacePort,
  };
}

function typedPayload<Payload>(value: unknown): Payload {
  return value as Payload;
}

function exactQueryPayload<Payload>(
  value: unknown,
  expectedFields: readonly string[],
): Payload {
  const normalized = parseNormalizedValue(value);
  if (typeof normalized !== "object" || normalized === null || Array.isArray(normalized)) {
    throw new TypeError("query payload must be an object");
  }
  const keys = Reflect.ownKeys(normalized);
  if (
    keys.some((key) => typeof key !== "string") ||
    keys.length !== expectedFields.length ||
    expectedFields.some((field) => !Object.prototype.hasOwnProperty.call(normalized, field))
  ) {
    throw new TypeError("query payload fields do not match the operation schema");
  }
  return normalized as unknown as Payload;
}

interface WorkspaceInvocationQuery {
  readonly invocationId: string;
  readonly requestDigest: Digest;
  readonly authority: WorkspaceAuthoritySnapshot;
  readonly now: number;
}

interface AuthorizedControlQuery {
  readonly authority: ControlAuthoritySnapshot;
  readonly now: number;
}

interface SessionEventsQuery extends AuthorizedControlQuery {
  readonly afterSequence: number;
  readonly limit: number;
}

interface SessionBlobQuery extends AuthorizedControlQuery {
  // Content digest of the externalized payload (a checkpoint's payloadDigest).
  readonly digest: Digest;
}

// The hydrated form of one externalized payload. `null` when the current state
// references no blob with that digest.
export interface SessionBlobRead {
  readonly digest: Digest;
  readonly encodedBytes: number;
  readonly bytes: Uint8Array;
}

function assertAuthorizedSessionRead(
  state: SessionAggregateState,
  query: AuthorizedControlQuery,
): void {
  const authority = validatedAuthority(
    query.authority,
    {
      tenantId: state.tenantId,
      subjectKind: "session",
      subjectId: state.sessionId,
    },
    query.now,
    "session.read",
  );
  // Like admission and broker authority, a Session is readable only by its owner.
  if (authority.actorUserId !== state.userId) {
    controlError("PERMISSION_DENIED", "session read authority belongs to another principal");
  }
  if (authority.currentAuthorizationGeneration !== state.authorizationGeneration) {
    controlError("STALE_GENERATION", "session read authority is stale");
  }
}

interface CapabilityGenerationQuery extends AuthorizedControlQuery {
  readonly candidateGeneration: number;
}

interface AuditEntriesQuery extends AuthorizedControlQuery {
  readonly afterSequence: number;
  readonly limit: number;
}

export class SessionCell extends DurableObject<StateHostEnvironment> {
  static readonly hostProfile = CELLD_HOST_PROFILE;
  private readonly brokerPolicy: SessionBrokerPolicy | null;
  private readonly admissionTTLms: number | null;
  private readonly admissionClock: () => number;
  private readonly kernel: TransactionalAggregateKernel<
    SessionAggregateState,
    CreateSessionStateInput,
    SessionCommand,
    StoredSessionCommandOutcome,
    SessionCommandOutcome,
    SessionApplyContext,
    ApplySessionCommandResult
  >;

  constructor(
    state: StateHostContext,
    environment: StateHostEnvironment,
    clock: () => number = Date.now,
  ) {
    super(state, environment);
    this.admissionTTLms = sessionAdmissionHostPolicy(environment.CIRCULUSD_STATE_ADMISSION_POLICY);
    this.admissionClock = clock;
    this.brokerPolicy = sessionBrokerHostPolicy(environment.CIRCULUSD_STATE_BROKER_POLICY);
    this.kernel = new TransactionalAggregateKernel(
      state,
      sessionAdapter,
      cellRoute(state, environment, "SESSION_CELL"),
      clock,
      sessionHistoryCompanion,
    );
  }

  initializeSession(request: unknown): Promise<HostRpcResponse<InitializationResult>> {
    return invokeHostRpc(
      "session.initialize",
      request,
      typedPayload<CreateSessionStateInput>,
      (input) => this.kernel.initialize(input),
    );
  }

  planSessionTurnAdmission(request: unknown): Promise<HostRpcResponse<unknown>> {
    return invokeHostRpc("session.execute", request, parseSessionAdmissionPlanningRequest, async (input) => {
      const ttl = this.admissionTTLms;
      if (ttl === null) sessionError("FAILED_PRECONDITION", "trusted Session admission policy is unavailable");
      return this.kernel.query(input, async (state, query, context) => {
        assertSessionAdmissionPlanningAuthority(state, query);
        await validateSessionAdmissionPlanningDigests(query);
        const receipt = state.turnAdmissionReceipts.find((candidate) => candidate.idempotencyKeyDigest === query.idempotencyKeyDigest) ??
          await new SessionHistoryStore(context.transaction, context.stored.manifest.sessionHistory, state)
            .admissionReceipt(query.idempotencyKeyDigest);
        return planSessionAdmission(state, query, receipt, this.admissionClock(), ttl);
      });
    });
  }

  brokerSession(request: unknown): Promise<HostRpcResponse<SessionBrokerTurn | SessionBrokerOperationReceipt | SessionBrokerReceiptValue>> {
    return invokeHostRpc("session.execute", request, parseTypedBrokerPayload, async (input) => {
      const policy = this.brokerPolicy;
      if (policy === null) sessionError("FAILED_PRECONDITION", "trusted Session broker runtime policy is unavailable");
      if (input.operation === "read-turn" || input.operation === "lookup-operation") {
        return this.kernel.query(input, async (state, query, context) => {
          assertSessionBrokerAuthority(state, query.authority);
          if (query.operation === "read-turn") return readSessionBrokerTurn(state, policy);
          if (query.operation !== "lookup-operation") sessionError("INVALID_ARGUMENT", "broker query kind changed");
          const operationKeyDigest = await brokerLookupKey(query.body.operationKey);
          const receipt = state.broker?.receipts.find((candidate) => candidate.kind === query.body.kind && candidate.operationKeyDigest === operationKeyDigest) ??
            await new SessionHistoryStore(context.transaction, context.stored.manifest.sessionHistory, state)
              .brokerReceipt(query.body.kind, query.body.operationKey, operationKeyDigest);
          return sessionBrokerLookupResult(query.body, receipt, context.readBlob);
        });
      }
      const result = await this.kernel.execute(await brokerCommand(input, policy));
      if (result.outcome.kind !== "broker_result") sessionError("FAILED_PRECONDITION", "broker operation returned another outcome kind");
      return result.outcome.result;
    });
  }

  executeSessionCommand(
    request: unknown,
  ): Promise<HostRpcResponse<CommittedCommandResult<SessionCommandOutcome>>> {
    return invokeHostRpc(
      "session.execute",
      request,
      (payload) => {
        const command = typedPayload<SessionCommand>(payload);
        if (command !== null && typeof command === "object" && command.kind === "broker_operation") {
          sessionError("INVALID_ARGUMENT", "broker operations require the typed authority-owned entrypoint");
        }
        return command;
      },
      (command) => this.kernel.execute(command),
    );
  }

  readSession(
    request: unknown,
  ): Promise<HostRpcResponse<SessionAggregateState>> {
    return invokeHostRpc(
      "session.read",
      request,
      (payload) => exactQueryPayload<AuthorizedControlQuery>(
        payload,
        ["authority", "now"],
      ),
      (input) => this.kernel.query(
        input,
        (state, query) => {
          assertAuthorizedSessionRead(state, query);
          return state;
        },
      ),
    );
  }

  // Hydrates one payload that `session.read` returned only a reference to
  // (storage redesign stage B). Authorized exactly like `session.read`.
  readSessionBlob(
    request: unknown,
  ): Promise<HostRpcResponse<SessionBlobRead | null>> {
    return invokeHostRpc(
      "session.read-blob",
      request,
      (payload) => {
        const query = exactQueryPayload<SessionBlobQuery>(
          payload,
          ["authority", "now", "digest"],
        );
        return { ...query, digest: parseDigest(query.digest, "$digest") };
      },
      async (input) => {
        const bytes = await this.kernel.queryBlob(
          input,
          assertAuthorizedSessionRead,
          (query) => query.digest,
        );
        if (bytes === undefined) {
          return null;
        }
        return { digest: input.digest, encodedBytes: bytes.byteLength, bytes };
      },
    );
  }

  readSessionEvents(
    request: unknown,
  ): Promise<HostRpcResponse<SessionPublicEventReplay>> {
    return invokeHostRpc(
      "session.read-events",
      request,
      (payload) => exactQueryPayload<SessionEventsQuery>(
        payload,
        ["authority", "now", "afterSequence", "limit"],
      ),
      (input) => this.kernel.query(
        input,
        async (state, query, context) => {
          assertAuthorizedSessionRead(state, query);
          const archivedEvents = await new SessionHistoryStore(context.transaction,
            context.stored.manifest.sessionHistory, state).events(state, query.afterSequence, query.limit);
          return replaySessionPublicEvents(
            state,
            query.afterSequence,
            query.limit,
            archivedEvents,
          );
        },
      ),
    );
  }
}

export class WorkspaceCell extends DurableObject<StateHostEnvironment> {
  static readonly hostProfile = CELLD_HOST_PROFILE;
  private readonly kernel: TransactionalAggregateKernel<
    WorkspaceAggregateState,
    CreateWorkspaceStateInput,
    WorkspaceCommand,
    WorkspaceCommandOutcome
  >;

  constructor(
    state: StateHostContext,
    environment: StateHostEnvironment,
    clock: () => number = Date.now,
  ) {
    super(state, environment);
    this.kernel = new TransactionalAggregateKernel(
      state,
      workspaceAdapter,
      cellRoute(state, environment, "WORKSPACE_CELL"),
      clock,
    );
  }

  initializeWorkspace(request: unknown): Promise<HostRpcResponse<InitializationResult>> {
    return invokeHostRpc(
      "workspace.initialize",
      request,
      typedPayload<CreateWorkspaceStateInput>,
      (input) => this.kernel.initialize(input),
    );
  }

  executeWorkspaceCommand(
    request: unknown,
  ): Promise<HostRpcResponse<CommittedCommandResult<WorkspaceCommandOutcome>>> {
    return invokeHostRpc(
      "workspace.execute",
      request,
      typedPayload<WorkspaceCommand>,
      (command) => this.kernel.execute(command),
    );
  }

  lookupWorkspaceInvocation(
    request: unknown,
  ): Promise<HostRpcResponse<WorkspaceInvocationRecord | null>> {
    return invokeHostRpc(
      "workspace.lookup-invocation",
      request,
      (payload) => exactQueryPayload<WorkspaceInvocationQuery>(
        payload,
        ["invocationId", "requestDigest", "authority", "now"],
      ),
      (input) => this.kernel.query(
        input,
        (state, query) => lookupWorkspaceInvocation(
          state,
          query.invocationId,
          query.requestDigest,
          query.authority,
          query.now,
        ),
      ),
    );
  }
}

export class UserCell extends DurableObject<StateHostEnvironment> {
  static readonly hostProfile = CELLD_HOST_PROFILE;
  private readonly kernel: TransactionalAggregateKernel<
    UserAggregateState,
    CreateUserStateInput,
    UserCommand,
    UserCommandOutcome
  >;

  constructor(state: StateHostContext, environment: StateHostEnvironment) {
    super(state, environment);
    this.kernel = new TransactionalAggregateKernel(
      state,
      userAdapter,
      cellRoute(state, environment, "USER_CELL"),
    );
  }

  initializeUser(request: unknown): Promise<HostRpcResponse<InitializationResult>> {
    return invokeHostRpc(
      "user.initialize",
      request,
      typedPayload<CreateUserStateInput>,
      (input) => this.kernel.initialize(input),
    );
  }

  executeUserCommand(
    request: unknown,
  ): Promise<HostRpcResponse<CommittedCommandResult<UserCommandOutcome>>> {
    return invokeHostRpc(
      "user.execute",
      request,
      typedPayload<UserCommand>,
      (command) => this.kernel.execute(command),
    );
  }

  readUser(
    request: unknown,
  ): Promise<HostRpcResponse<UserAggregateState>> {
    return invokeHostRpc(
      "user.read",
      request,
      (payload) => exactQueryPayload<AuthorizedControlQuery>(
        payload,
        ["authority", "now"],
      ),
      (input) => this.kernel.query(
        input,
        (state, query) => readUserState(state, query.authority, query.now),
      ),
    );
  }
}

export class ExtensionStateCell extends DurableObject<StateHostEnvironment> {
  static readonly hostProfile = CELLD_HOST_PROFILE;
  private readonly kernel: TransactionalAggregateKernel<
    ExtensionStateAggregateState,
    CreateExtensionStateInput,
    ExtensionStateCommand,
    ExtensionStateCommandOutcome
  >;

  constructor(state: StateHostContext, environment: StateHostEnvironment) {
    super(state, environment);
    this.kernel = new TransactionalAggregateKernel(
      state,
      extensionStateAdapter,
      cellRoute(state, environment, "EXTENSION_STATE_CELL"),
    );
  }

  initializeExtensionState(
    request: unknown,
  ): Promise<HostRpcResponse<InitializationResult>> {
    return invokeHostRpc(
      "extension-state.initialize",
      request,
      typedPayload<CreateExtensionStateInput>,
      (input) => this.kernel.initialize(input),
    );
  }

  executeExtensionStateCommand(
    request: unknown,
  ): Promise<HostRpcResponse<CommittedCommandResult<ExtensionStateCommandOutcome>>> {
    return invokeHostRpc(
      "extension-state.execute",
      request,
      typedPayload<ExtensionStateCommand>,
      (command) => this.kernel.execute(command),
    );
  }

  readExtensionState(
    request: unknown,
  ): Promise<HostRpcResponse<ExtensionStateAggregateState>> {
    return invokeHostRpc(
      "extension-state.read",
      request,
      (payload) => exactQueryPayload<AuthorizedControlQuery>(
        payload,
        ["authority", "now"],
      ),
      (input) => this.kernel.query(
        input,
        (state, query) => readExtensionState(state, query.authority, query.now),
      ),
    );
  }
}

export class CapabilityGenerationCell extends DurableObject<StateHostEnvironment> {
  static readonly hostProfile = CELLD_HOST_PROFILE;
  private readonly kernel: TransactionalAggregateKernel<
    CapabilityGenerationAggregateState,
    CreateCapabilityGenerationStateInput,
    CapabilityGenerationCommand,
    CapabilityGenerationCommandOutcome
  >;

  constructor(state: StateHostContext, environment: StateHostEnvironment) {
    super(state, environment);
    this.kernel = new TransactionalAggregateKernel(
      state,
      capabilityGenerationAdapter,
      cellRoute(state, environment, "CAPABILITY_GENERATION_CELL"),
    );
  }

  initializeCapabilityGeneration(
    request: unknown,
  ): Promise<HostRpcResponse<InitializationResult>> {
    return invokeHostRpc(
      "capability-generation.initialize",
      request,
      typedPayload<CreateCapabilityGenerationStateInput>,
      (input) => this.kernel.initialize(input),
    );
  }

  executeCapabilityGenerationCommand(
    request: unknown,
  ): Promise<HostRpcResponse<CommittedCommandResult<CapabilityGenerationCommandOutcome>>> {
    return invokeHostRpc(
      "capability-generation.execute",
      request,
      typedPayload<CapabilityGenerationCommand>,
      (command) => this.kernel.execute(command),
    );
  }

  assertCurrentCapabilityGeneration(
    request: unknown,
  ): Promise<HostRpcResponse<{ readonly current: true; readonly version: number }>> {
    return invokeHostRpc(
      "capability-generation.assert-current",
      request,
      (payload) => exactQueryPayload<CapabilityGenerationQuery>(
        payload,
        ["candidateGeneration", "authority", "now"],
      ),
      (input) => this.kernel.query(
        input,
        (state, query) => {
          assertCurrentCapabilityGeneration(
            state,
            query.candidateGeneration,
            query.authority,
            query.now,
          );
          return { current: true as const, version: state.revision };
        },
      ),
    );
  }
}

export class AuditCell extends DurableObject<StateHostEnvironment> {
  static readonly hostProfile = CELLD_HOST_PROFILE;
  private readonly kernel: AuditCellKernel;

  constructor(state: StateHostContext, environment: StateHostEnvironment) {
    super(state, environment);
    this.kernel = new AuditCellKernel(
      state,
      cellRoute(state, environment, "AUDIT_CELL"),
    );
  }

  initializeAudit(request: unknown): Promise<HostRpcResponse<InitializationResult>> {
    return invokeHostRpc(
      "audit.initialize",
      request,
      typedPayload<CreateAuditStateInput>,
      (input) => this.kernel.initialize(input),
    );
  }

  executeAuditCommand(
    request: unknown,
  ): Promise<HostRpcResponse<CommittedCommandResult<AuditCommandOutcome>>> {
    return invokeHostRpc(
      "audit.execute",
      request,
      typedPayload<AuditCommand>,
      (command) => this.kernel.execute(command),
    );
  }

  readAuditEntries(
    request: unknown,
  ): Promise<HostRpcResponse<AuditEntry[]>> {
    return invokeHostRpc(
      "audit.read",
      request,
      (payload) => exactQueryPayload<AuditEntriesQuery>(
        payload,
        ["afterSequence", "limit", "authority", "now"],
      ),
      (input) => this.kernel.read(
        input.afterSequence,
        input.limit,
        input.authority,
        input.now,
      ),
    );
  }
}
