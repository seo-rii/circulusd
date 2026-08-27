import { DurableObject } from "cloudflare:workers";

import { parseNormalizedValue, type Digest } from "@circulusd/protocol-types";

import {
  applySessionCommand,
  createSessionState,
  validateSessionState,
  type CreateSessionStateInput,
  type SessionAggregateState,
  type SessionCommand,
  type SessionCommandOutcome,
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
  SessionCommandOutcome
> = {
  kind: "session",
  cellName: (initialization) =>
    sessionCellName(initialization.tenantId, initialization.sessionId),
  create: createSessionState,
  validate: validateSessionState,
  apply: applySessionCommand,
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

interface CapabilityGenerationQuery extends AuthorizedControlQuery {
  readonly candidateGeneration: number;
}

interface AuditEntriesQuery extends AuthorizedControlQuery {
  readonly afterSequence: number;
  readonly limit: number;
}

export class SessionCell extends DurableObject<StateHostEnvironment> {
  static readonly hostProfile = CELLD_HOST_PROFILE;
  private readonly kernel: TransactionalAggregateKernel<
    SessionAggregateState,
    CreateSessionStateInput,
    SessionCommand,
    SessionCommandOutcome
  >;

  constructor(state: StateHostContext, environment: StateHostEnvironment) {
    super(state, environment);
    this.kernel = new TransactionalAggregateKernel(
      state,
      sessionAdapter,
      cellRoute(state, environment, "SESSION_CELL"),
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

  executeSessionCommand(
    request: unknown,
  ): Promise<HostRpcResponse<CommittedCommandResult<SessionCommandOutcome>>> {
    return invokeHostRpc(
      "session.execute",
      request,
      typedPayload<SessionCommand>,
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
          if (
            authority.currentAuthorizationGeneration !==
            state.authorizationGeneration
          ) {
            controlError(
              "STALE_GENERATION",
              "session read authority is stale",
            );
          }
          return state;
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

  constructor(state: StateHostContext, environment: StateHostEnvironment) {
    super(state, environment);
    this.kernel = new TransactionalAggregateKernel(
      state,
      workspaceAdapter,
      cellRoute(state, environment, "WORKSPACE_CELL"),
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
