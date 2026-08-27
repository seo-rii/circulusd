import { describe, expect, it } from "vitest";
import { DurableObject } from "cloudflare:workers";

import {
  PROTOCOL_MAJOR,
  PROTOCOL_MINOR,
  PROTOCOL_NAME,
  digestBytes,
  encodeCanonicalCbor,
  type Digest,
} from "@circulusd/protocol-types";

import {
  AuditCell,
  CELLD_HOST_PROFILE,
  CapabilityGenerationCell,
  ExtensionStateCell,
  REFERENCE_HOST_PROFILE,
  SessionCell,
  UserCell,
  WorkspaceCell,
  auditCellName,
  capabilityGenerationCellName,
  extensionStateCellName,
  sessionCellName,
  userCellName,
  workspaceCellName,
} from "../src/host/index.ts";
import type { AggregateAdapter } from "../src/host/contracts.ts";
import { TransactionalAggregateKernel } from "../src/host/kernel.ts";
import {
  HOST_RPC_CONTRACTS,
  type HostRpcOperation,
  type HostRpcResponse,
} from "../src/host/rpc.ts";
import type {
  AuditEventInput,
  ControlAuthoritySnapshot,
  CreateAuditStateInput,
  CreateCapabilityGenerationStateInput,
  CreateExtensionStateInput,
  CreateUserStateInput,
  ExtensionStateCommand,
  UserCommand,
} from "../src/control/index.ts";
import {
  turnInputDigest,
  type CreateSessionStateInput,
  type SessionCommand,
} from "../src/session/index.ts";
import type {
  CreateWorkspaceStateInput,
  WorkspaceAuthoritySnapshot,
  WorkspaceCommand,
} from "../src/workspace/index.ts";

interface FakeTransaction {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
}

const FAKE_DURABLE_OBJECT_VALUE_LIMIT = 2_000_000;

class FakeTransactionalStorage {
  readonly values = new Map<string, unknown>();
  revision = 0;
  callbackAttempts = 0;
  forceRetryCount = 0;
  observedGetBytes = 0;
  observedPutBytes = 0;
  private commitGate:
    | {
        reached: () => void;
        wait: Promise<void>;
      }
    | undefined;

  async transaction<T>(callback: (transaction: FakeTransaction) => Promise<T>): Promise<T> {
    for (let attempt = 0; attempt < 32; attempt += 1) {
      const expectedRevision = this.revision;
      const snapshot = new Map<string, unknown>();
      for (const [key, value] of this.values) {
        snapshot.set(key, structuredClone(value));
      }
      const writes = new Map<string, unknown>();
      const deletes = new Set<string>();
      const transaction: FakeTransaction = {
        get: async <Value>(key: string) => {
          const value = deletes.has(key)
            ? undefined
            : writes.has(key)
              ? writes.get(key)
              : snapshot.get(key);
          if (value !== undefined) {
            this.observedGetBytes += encodeCanonicalCbor(value).byteLength;
          }
          return value === undefined ? undefined : structuredClone(value) as Value;
        },
        put: async <Value>(key: string, value: Value) => {
          const encodedBytes = encodeCanonicalCbor(value);
          this.observedPutBytes += encodedBytes.byteLength;
          if (
            new TextEncoder().encode(key).byteLength + encodedBytes.byteLength >
            FAKE_DURABLE_OBJECT_VALUE_LIMIT
          ) {
            throw new Error("fake Durable Object key and value exceed 2 MB");
          }
          deletes.delete(key);
          writes.set(key, structuredClone(value));
        },
        delete: async (key: string) => {
          const existed = writes.delete(key) || snapshot.has(key);
          deletes.add(key);
          return existed;
        },
      };
      this.callbackAttempts += 1;
      const result = await callback(transaction);
      if (this.forceRetryCount > 0) {
        this.forceRetryCount -= 1;
        continue;
      }
      const gate = this.commitGate;
      if (gate !== undefined) {
        this.commitGate = undefined;
        gate.reached();
        await gate.wait;
      }
      if (expectedRevision !== this.revision) {
        continue;
      }
      if (writes.size > 0 || deletes.size > 0) {
        for (const key of deletes) {
          this.values.delete(key);
        }
        for (const [key, value] of writes) {
          this.values.set(key, structuredClone(value));
        }
        this.revision += 1;
      }
      return structuredClone(result);
    }
    throw new Error("fake transaction retry limit exceeded");
  }

  blockNextCommit(): { reached: Promise<void>; release: () => void } {
    let markReached!: () => void;
    let release!: () => void;
    const reached = new Promise<void>((resolve) => {
      markReached = resolve;
    });
    const wait = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.commitGate = { reached: markReached, wait };
    return { reached, release };
  }

  resetObservedIo(): void {
    this.observedGetBytes = 0;
    this.observedPutBytes = 0;
  }

  observedIoBytes(): number {
    return this.observedGetBytes + this.observedPutBytes;
  }

  corruptState(mutator: (state: Record<string, unknown>) => void): void {
    const chunkEntry = [...this.values].find(([, value]) => value instanceof Uint8Array);
    if (chunkEntry !== undefined) {
      const [key, value] = chunkEntry as [string, Uint8Array];
      const corrupted = value.slice();
      corrupted[corrupted.byteLength - 1] ^= 0xff;
      this.values.set(key, corrupted);
      this.revision += 1;
      return;
    }
    const entry = this.values.entries().next().value as [string, unknown] | undefined;
    if (entry === undefined) {
      throw new Error("no stored state to corrupt");
    }
    const [key, value] = entry;
    const record = structuredClone(value) as { state: Record<string, unknown> };
    mutator(record.state);
    this.values.set(key, record);
    this.revision += 1;
  }

  deleteStoredValue(key: string): void {
    if (!this.values.delete(key)) {
      throw new Error(`no stored value for ${key}`);
    }
    this.revision += 1;
  }
}

function stateWith(storage: FakeTransactionalStorage) {
  return { storage };
}

type FakeStateBindingName =
  | "SESSION_CELL"
  | "WORKSPACE_CELL"
  | "USER_CELL"
  | "EXTENSION_STATE_CELL"
  | "CAPABILITY_GENERATION_CELL"
  | "AUDIT_CELL";

function routedCellContext(
  storage: unknown,
  bindingName: FakeStateBindingName,
  logicalName: string,
) {
  const currentId = {
    logicalName,
    equals: (other: unknown) =>
      typeof other === "object" &&
      other !== null &&
      (other as { readonly logicalName?: unknown }).logicalName === logicalName,
    toString: () => `physical:${logicalName}`,
  };
  const namespace = {
    idFromName: (name: string) => ({
      logicalName: name,
      equals: (other: unknown) =>
        typeof other === "object" &&
        other !== null &&
        (other as { readonly logicalName?: unknown }).logicalName === name,
      toString: () => `physical:${name}`,
    }),
  };
  return {
    state: { id: currentId, storage } as never,
    environment: { [bindingName]: namespace },
  };
}

function rawUserCell(storage: FakeTransactionalStorage): UserCell {
  const route = routedCellContext(
    storage,
    "USER_CELL",
    userCellName("tenant-1", "user-1"),
  );
  return new UserCell(route.state, route.environment);
}

function userCell(storage: FakeTransactionalStorage) {
  const cell = rawUserCell(storage);
  return {
    initializeUser: (input: CreateUserStateInput) => hostRpcResult(
      "user.initialize",
      input,
      (request) => cell.initializeUser(request),
    ),
    executeUserCommand: (command: UserCommand) => hostRpcResult(
      "user.execute",
      command,
      (request) => cell.executeUserCommand(request),
    ),
    readUser: (authority: ControlAuthoritySnapshot, now: number) => hostRpcResult(
      "user.read",
      { authority, now },
      (request) => cell.readUser(request),
    ),
  };
}

function hostRpcRequest(
  operation: HostRpcOperation,
  payload: unknown,
  requestId = `request-${operation}`,
) {
  return {
    protocol: PROTOCOL_NAME,
    major: PROTOCOL_MAJOR,
    minor: PROTOCOL_MINOR,
    schemaDigest: HOST_RPC_CONTRACTS[operation].schemaDigest,
    requestId,
    payload,
  };
}

async function hostRpcResult<Result>(
  operation: HostRpcOperation,
  payload: unknown,
  invoke: (request: ReturnType<typeof hostRpcRequest>) => Promise<HostRpcResponse<Result>>,
): Promise<Result> {
  const response = await invoke(hostRpcRequest(operation, payload));
  if (!response.payload.ok) {
    throw Object.assign(new Error(response.payload.error.message), {
      code: response.payload.error.code,
    });
  }
  return response.payload.result as Result;
}

function userInitialization(
  overrides: Partial<CreateUserStateInput> = {},
): CreateUserStateInput {
  return {
    userId: "user-1",
    tenantId: "tenant-1",
    defaultExtensions: [{ id: "official/pdf", version: "1.0.0" }],
    defaultExecutionBackend: "nsjail",
    preferredAgentIsolation: null,
    modelConfiguration: { provider: "lan-model", model: "small" },
    mcpConfiguration: [{ id: "docs", configuration: { enabled: true } }],
    quotaProfile: "standard",
    ...overrides,
  };
}

function userAuthority(
  overrides: Partial<ControlAuthoritySnapshot> = {},
): ControlAuthoritySnapshot {
  return {
    serviceBinding: "state",
    tenantId: "tenant-1",
    actorUserId: "user-1",
    subjectKind: "user",
    subjectId: "user-1",
    roles: ["user"],
    permissions: ["user.preferences.write", "user.read"],
    authorizationGeneration: 1,
    currentAuthorizationGeneration: 1,
    issuedAt: 1,
    expiresAt: 10_000,
    ...overrides,
  };
}

function sessionAuthority(
  overrides: Partial<ControlAuthoritySnapshot> = {},
): ControlAuthoritySnapshot {
  return {
    serviceBinding: "state",
    tenantId: "tenant-1",
    actorUserId: "user-1",
    subjectKind: "session",
    subjectId: "session-1",
    roles: ["user"],
    permissions: ["session.read"],
    authorizationGeneration: 6,
    currentAuthorizationGeneration: 6,
    issuedAt: 1,
    expiresAt: 10_000,
    ...overrides,
  };
}

function userCommand(
  commandId = "command-preferences-1",
  overrides: Partial<UserCommand> = {},
): UserCommand {
  return {
    kind: "replace_preferences",
    commandId,
    expectedRevision: 0,
    now: 10,
    authority: userAuthority(),
    defaultExtensions: [{ id: "official/code", version: "2.0.0" }],
    defaultExecutionBackend: "docker",
    preferredAgentIsolation: {
      processScope: "tenant",
      outerIsolation: "none",
    },
    modelConfiguration: { provider: "lan-model", model: "large" },
    mcpConfiguration: [{ id: "search", configuration: { enabled: true } }],
    ...overrides,
  } as UserCommand;
}

const digest = (character: string): Digest =>
  `sha256:${character.repeat(64)}` as Digest;

function sessionInitialization(): CreateSessionStateInput {
  return {
    sessionId: "session-1",
    tenantId: "tenant-1",
    userId: "user-1",
    workspaceId: "workspace-1",
    runtimeRevisionDigest: digest("1"),
    policySnapshotDigest: digest("2"),
    emergencyOverlayDigest: digest("3"),
    engineKind: "low-level",
    adapterAbiVersion: 1,
    checkpointSchemaVersion: 1,
    placementGeneration: 4,
    sandboxGeneration: 5,
    authorizationGeneration: 6,
  };
}

async function enqueueSessionCommand(): Promise<SessionCommand> {
  const input = { message: "hello" };
  const payloadBytes = new TextEncoder().encode("genesis:turn-1");
  return {
    kind: "enqueue_turn",
    commandId: "enqueue-1",
    expectedEventSequence: 0,
    transactionTime: 100,
    turnId: "turn-1",
    input,
    inputDigest: await turnInputDigest(input),
    genesisCheckpoint: {
      kind: "genesis",
      engineKind: "low-level",
      adapterAbiVersion: 1,
      checkpointSchemaVersion: 1,
      runtimeRevisionDigest: digest("1"),
      sessionId: "session-1",
      turnId: "turn-1",
      checkpointSequence: 0,
      predecessorDigest: null,
      payloadEncoding: "opaque-v1",
      payloadBytes,
      payloadDigest: await digestBytes(payloadBytes),
    },
    turnLeaseGeneration: 10,
    leaseExpiresAt: 1_000,
  };
}

function workspaceInitialization(): CreateWorkspaceStateInput {
  return {
    workspaceId: "workspace-1",
    tenantId: "tenant-1",
    initialRootDigest: digest("0"),
  };
}

function workspaceAuthority(
  overrides: Partial<WorkspaceAuthoritySnapshot> = {},
): WorkspaceAuthoritySnapshot {
  return {
    purpose: "admission",
    serviceBinding: "workspace",
    tenantId: "tenant-1",
    userId: "user-1",
    sessionId: "session-workspace-1",
    workspaceId: "workspace-1",
    turnId: "turn-workspace-1",
    runtimeRevision: "runtime-1",
    policySnapshotDigest: digest("4"),
    emergencyOverlayDigest: digest("5"),
    effectivePermissions: ["workspace.read", "workspace.write"],
    sessionStatus: "active",
    turnStatus: "active",
    turnLeaseActive: true,
    turnLeaseExpiresAt: 10_000,
    effectStatus: "dispatched",
    effectId: "effect-workspace-1",
    invocationId: "invocation-workspace-1",
    requestDigest: digest("6"),
    replayPolicy: "idempotency-key",
    dispatchAttempt: 1,
    turnLeaseGeneration: 3,
    placementGeneration: 5,
    sandboxGeneration: 7,
    sandboxId: "sandbox-workspace-1",
    backend: "nsjail",
    authorizationGeneration: 11,
    issuedAt: 0,
    expiresAt: 10_000,
    ...overrides,
  };
}

function acquireWorkspaceCommand(): WorkspaceCommand {
  return {
    kind: "acquire_write_lease",
    expectedEventSequence: 0,
    now: 100,
    authority: workspaceAuthority(),
    requestedLeaseId: "lease-workspace-1",
    sandboxId: "sandbox-workspace-1",
    backend: "nsjail",
    projectionGeneration: 13,
    requestedLeaseTtlMs: 200,
    requestedMaximumHoldMs: 500,
    acquireDeadline: 1_000,
    waitPolicy: "queue",
  };
}

function extensionInitialization(): CreateExtensionStateInput {
  return {
    tenantId: "tenant-1",
    scopeKind: "workspace",
    scopeId: "workspace-1",
    extensionId: "official/pdf",
    extensionSchemaVersion: 1,
    stateGeneration: 1,
    predecessor: null,
    value: { outputFormat: "pdf" },
  };
}

function extensionAuthority(
  permissions: ControlAuthoritySnapshot["permissions"],
): ControlAuthoritySnapshot {
  return {
    serviceBinding: "state",
    tenantId: "tenant-1",
    actorUserId: "admin-1",
    subjectKind: "workspace",
    subjectId: "workspace-1",
    roles: ["tenant-admin"],
    permissions,
    authorizationGeneration: 4,
    currentAuthorizationGeneration: 4,
    issuedAt: 1,
    expiresAt: 10_000,
  };
}

function generationInitialization(): CreateCapabilityGenerationStateInput {
  return {
    tenantId: "tenant-1",
    subjectKind: "workspace",
    subjectId: "workspace-1",
    generationKind: "workspace-security",
    initialGeneration: 7,
  };
}

function auditInitialization(): CreateAuditStateInput {
  return { tenantId: "tenant-1" };
}

function auditAuthority(
  permissions: ControlAuthoritySnapshot["permissions"] = ["audit.append", "audit.read"],
): ControlAuthoritySnapshot {
  return {
    serviceBinding: "state",
    tenantId: "tenant-1",
    actorUserId: "admin-1",
    subjectKind: "tenant",
    subjectId: "tenant-1",
    roles: ["tenant-admin"],
    permissions,
    authorizationGeneration: 3,
    currentAuthorizationGeneration: 3,
    issuedAt: 1,
    expiresAt: 10_000,
  };
}

function auditEvent(): AuditEventInput {
  return {
    timestamp: 100,
    actorUserId: "admin-1",
    eventType: "host.command",
    result: "success",
    correlation: {
      userId: "user-1",
      sessionId: null,
      turnId: null,
      effectId: null,
      runtimeRevision: null,
      workspaceId: "workspace-1",
      agentShardId: null,
      placementGeneration: null,
      executionBackend: null,
      executionEnvironmentRevision: null,
      sandboxId: null,
      sandboxGeneration: null,
      invocationId: "audit-invocation-1",
    },
    metadata: { source: "host-test" },
  };
}

describe("command host transactional kernel", () => {
  it("labels reference and unqualified celld profiles without production claims", () => {
    expect(REFERENCE_HOST_PROFILE).toMatchObject({
      productionEligible: false,
      processLocal: true,
      restartPersistence: false,
    });
    expect(CELLD_HOST_PROFILE).toMatchObject({
      productionEligible: false,
      conformanceClaimed: false,
    });
    expect(SessionCell.hostProfile).toBe(CELLD_HOST_PROFILE);
    expect(SessionCell.hostProfile.productionEligible).toBe(false);
    expect(SessionCell.hostProfile.conformanceClaimed).toBe(false);
    expect(sessionCellName("tenant/a", "session-b")).not.toBe(
      sessionCellName("tenant", "a/session-b"),
    );
    expect(userCellName("tenant-1", "user-1")).toBe(
      userCellName("tenant-1", "user-1"),
    );
  });

  it("fails closed without transactional storage or initialization", async () => {
    expect(() => new UserCell(null as never)).toThrowError(
      expect.objectContaining({ code: "STORAGE_CONTRACT" }),
    );
    expect(() => new UserCell({ storage: {} } as never)).toThrowError(
      expect.objectContaining({ code: "STORAGE_CONTRACT" }),
    );
    const bypassRoute = routedCellContext(
      {
        transaction: async () => ({ version: 0, replayed: false }),
      },
      "USER_CELL",
      userCellName("tenant-1", "user-1"),
    );
    const bypassed = new UserCell(bypassRoute.state, bypassRoute.environment);
    await expect(hostRpcResult(
      "user.initialize",
      userInitialization(),
      (request) => bypassed.initializeUser(request),
    )).rejects.toMatchObject({ code: "STORAGE_CONTRACT" });

    const storage = new FakeTransactionalStorage();
    const cell = userCell(storage);
    await expect(cell.executeUserCommand(userCommand())).rejects.toMatchObject({
      code: "NOT_INITIALIZED",
    });
    expect(storage.values.size).toBe(0);
  });

  it("initializes exactly once and binds the canonical initialization digest", async () => {
    const storage = new FakeTransactionalStorage();
    const cell = userCell(storage);
    const initialization = userInitialization();

    const results = await Promise.all([
      cell.initializeUser(initialization),
      cell.initializeUser(structuredClone(initialization)),
    ]);
    expect(results.map((result) => result.replayed).sort()).toEqual([false, true]);
    expect(results.every((result) => result.version === 0)).toBe(true);
    expect(storage.values.size).toBe(3);

    initialization.modelConfiguration = { provider: "tampered" };
    const stored = await cell.readUser(userAuthority({ permissions: ["user.read"] }), 10);
    expect(stored.modelConfiguration).toEqual({ provider: "lan-model", model: "small" });

    await expect(
      cell.initializeUser(userInitialization({ quotaProfile: "different" })),
    ).rejects.toMatchObject({ code: "INITIALIZATION_CONFLICT" });
  });

  it("does not recreate an aggregate after either durable header key is lost", async () => {
    for (const lostSuffix of [
      ".aggregate.v2.manifest",
      ".aggregate.v2.anchor",
    ]) {
      const storage = new FakeTransactionalStorage();
      const cell = userCell(storage);
      await cell.initializeUser(userInitialization());
      await cell.executeUserCommand(userCommand(`header-loss-${lostSuffix}`));
      const lostKey = [...storage.values.keys()].find((key) =>
        key.endsWith(lostSuffix));
      expect(lostKey).toBeDefined();
      storage.values.delete(lostKey!);
      storage.revision += 1;

      await expect(
        cell.initializeUser(userInitialization()),
      ).rejects.toMatchObject({ code: "CORRUPT_STATE" });
      expect(storage.values.has(lostKey!)).toBe(false);
    }
  });

  it("binds initialization replay to the exact canonical input, not only derived state", async () => {
    interface State {
      readonly version: number;
      readonly value: string;
    }
    interface Initialization {
      readonly value: string;
    }
    const adapter: AggregateAdapter<State, Initialization, null, null> = {
      kind: "initialization-binding-test",
      create: (input) => ({ version: 0, value: input.value }),
      validate: () => undefined,
      apply: async (state) => ({ state, outcome: null, replayed: true }),
      version: (state) => state.version,
    };
    const kernel = new TransactionalAggregateKernel(
      stateWith(new FakeTransactionalStorage()),
      adapter,
    );
    await expect(kernel.initialize({ value: "same-derived-state" })).resolves.toMatchObject({
      replayed: false,
    });
    await expect(kernel.initialize({
      value: "same-derived-state",
      ignoredByCreate: true,
    } as Initialization)).rejects.toMatchObject({ code: "INITIALIZATION_CONFLICT" });
  });

  it("lets one simultaneous conflicting initialization win", async () => {
    const storage = new FakeTransactionalStorage();
    const cell = userCell(storage);
    const results = await Promise.allSettled([
      cell.initializeUser(userInitialization()),
      cell.initializeUser(userInitialization({ quotaProfile: "restricted" })),
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    const rejection = results.find((result) => result.status === "rejected");
    expect(rejection).toMatchObject({
      status: "rejected",
      reason: expect.objectContaining({ code: "INITIALIZATION_CONFLICT" }),
    });
    expect(storage.values.size).toBe(3);
  });

  it("serializes simultaneous commands without a lost update", async () => {
    const storage = new FakeTransactionalStorage();
    const cell = userCell(storage);
    await cell.initializeUser(userInitialization());

    const command = userCommand();
    const results = await Promise.all([
      cell.executeUserCommand(command),
      cell.executeUserCommand(structuredClone(command)),
    ]);
    expect(results.map((result) => result.replayed).sort()).toEqual([false, true]);
    expect(results.every((result) => result.version === 1)).toBe(true);
    expect(storage.values.size).toBe(3);

    const snapshot = await cell.readUser(userAuthority({ permissions: ["user.read"] }), 20);
    expect(snapshot.revision).toBe(1);
    expect(snapshot.commandReceipts).toHaveLength(1);

    await expect(
      cell.executeUserCommand(userCommand("command-preferences-1", {
        defaultExecutionBackend: "firecracker",
      })),
    ).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
  });

  it("allows one of two distinct CAS contenders and rejects the stale writer", async () => {
    const storage = new FakeTransactionalStorage();
    const cell = userCell(storage);
    await cell.initializeUser(userInitialization());

    const contenders = await Promise.allSettled([
      cell.executeUserCommand(userCommand("contender-a")),
      cell.executeUserCommand(userCommand("contender-b", {
        defaultExecutionBackend: "firecracker",
      })),
    ]);
    expect(contenders.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    const rejection = contenders.find((result) => result.status === "rejected");
    expect(rejection).toMatchObject({
      status: "rejected",
      reason: expect.objectContaining({ code: "CONFLICT" }),
    });
    const snapshot = await cell.readUser(userAuthority({ permissions: ["user.read"] }), 20);
    expect(snapshot.revision).toBe(1);
    expect(snapshot.commandReceipts).toHaveLength(1);
  });

  it("rolls back failed applies and deterministically survives a transaction retry", async () => {
    const storage = new FakeTransactionalStorage();
    const cell = userCell(storage);
    await cell.initializeUser(userInitialization());

    await expect(
      cell.executeUserCommand(userCommand("stale", { expectedRevision: 9 })),
    ).rejects.toMatchObject({ code: "CONFLICT" });
    let snapshot = await cell.readUser(userAuthority({ permissions: ["user.read"] }), 20);
    expect(snapshot.revision).toBe(0);
    expect(snapshot.commandReceipts).toEqual([]);

    const attemptsBefore = storage.callbackAttempts;
    storage.forceRetryCount = 1;
    const committed = await cell.executeUserCommand(userCommand("retried"));
    expect(committed).toMatchObject({ version: 1, replayed: false });
    expect(storage.callbackAttempts - attemptsBefore).toBe(2);
    snapshot = await cell.readUser(userAuthority({ permissions: ["user.read"] }), 20);
    expect(snapshot.revision).toBe(1);
    expect(snapshot.commandReceipts).toHaveLength(1);
  });

  it("rejects a replay result that changes the supposedly committed state", async () => {
    interface State {
      readonly version: number;
      readonly value: number;
    }
    const adapter: AggregateAdapter<State, State, null, { readonly value: number }> = {
      kind: "replay-state-test",
      create: (input) => input,
      validate: () => undefined,
      apply: async (state) => ({
        state: { version: state.version + 1, value: state.value + 1 },
        outcome: { value: state.value + 1 },
        replayed: true,
      }),
      version: (state) => state.version,
    };
    const kernel = new TransactionalAggregateKernel(
      stateWith(new FakeTransactionalStorage()),
      adapter,
    );
    await kernel.initialize({ version: 0, value: 0 });
    await expect(kernel.execute(null)).rejects.toMatchObject({
      code: "INVALID_AGGREGATE_OUTPUT",
    });
    await expect(kernel.query(null, (state) => state)).resolves.toEqual({
      version: 0,
      value: 0,
    });
  });

  it("chunks valid aggregates below the DO value limit and atomically deletes stale chunks", async () => {
    interface State {
      readonly version: number;
      readonly payload: Uint8Array;
    }
    const adapter: AggregateAdapter<State, State, Uint8Array, number> = {
      kind: "chunked-state-test",
      create: (input) => input,
      validate: (state) => {
        if (
          !Number.isSafeInteger(state.version) ||
          state.version < 0 ||
          !(state.payload instanceof Uint8Array) ||
          state.payload.byteLength > 4 * 1_048_576
        ) {
          throw new Error("invalid chunk test state");
        }
      },
      apply: async (state, payload) => ({
        state: { version: state.version + 1, payload },
        outcome: payload.byteLength,
        replayed: false,
      }),
      version: (state) => state.version,
    };
    const storage = new FakeTransactionalStorage();
    const kernel = new TransactionalAggregateKernel(stateWith(storage), adapter);
    const largePayload = new Uint8Array(2_500_000).fill(7);

    await expect(
      kernel.initialize({ version: 0, payload: largePayload }),
    ).resolves.toEqual({ version: 0, replayed: false });
    expect(storage.values.size).toBeGreaterThan(2);
    for (const [key, value] of storage.values) {
      const encodedValueBytes = value instanceof Uint8Array
        ? value.byteLength + 9
        : encodeCanonicalCbor(value).byteLength;
      expect(new TextEncoder().encode(key).byteLength + encodedValueBytes).toBeLessThanOrEqual(
        FAKE_DURABLE_OBJECT_VALUE_LIMIT,
      );
    }

    const smallStorage = new FakeTransactionalStorage();
    const smallKernel = new TransactionalAggregateKernel(stateWith(smallStorage), adapter);
    await smallKernel.initialize({ version: 0, payload: new Uint8Array([9]) });
    const staleChunkKeys = [...smallStorage.values]
      .filter(([, value]) => value instanceof Uint8Array)
      .map(([key]) => key);
    await expect(smallKernel.execute(new Uint8Array([1, 2, 3]))).resolves.toMatchObject({
      version: 1,
      outcome: 3,
    });
    expect(smallStorage.values.size).toBe(3);
    expect(staleChunkKeys.every((key) => !smallStorage.values.has(key))).toBe(true);

    const chunkKey = [...smallStorage.values].find(
      ([, value]) => value instanceof Uint8Array,
    )?.[0];
    expect(chunkKey).toBeDefined();
    smallStorage.deleteStoredValue(chunkKey!);
    await expect(smallKernel.query(null, (state) => state)).rejects.toMatchObject({
      code: "CORRUPT_STATE",
    });
  }, 30_000);

  it("rejects an aggregate that cannot be decoded within the host item budget", async () => {
    interface State {
      readonly version: number;
      readonly payload: readonly null[];
    }
    const adapter: AggregateAdapter<State, State, null, null> = {
      kind: "item-budget-test",
      create: (input) => input,
      validate: (state) => {
        if (state.version !== 0 || !Array.isArray(state.payload)) {
          throw new Error("invalid item budget test state");
        }
      },
      apply: async (state) => ({ state, outcome: null, replayed: true }),
      version: (state) => state.version,
    };
    const storage = new FakeTransactionalStorage();
    const kernel = new TransactionalAggregateKernel(stateWith(storage), adapter);

    await expect(
      kernel.initialize({
        version: 0,
        payload: Array.from({ length: 100_000 }, () => null),
      }),
    ).rejects.toMatchObject({ code: "INVALID_AGGREGATE_OUTPUT" });
    expect(storage.values.size).toBe(0);
  }, 30_000);

  it("keeps aggregate records below the 128 MiB isolate amplification budget", async () => {
    interface State {
      readonly version: number;
      readonly payload: Uint8Array;
    }
    const adapter: AggregateAdapter<State, State, null, null> = {
      kind: "isolate-memory-budget-test",
      create: (input) => input,
      validate: () => undefined,
      apply: async (state) => ({ state, outcome: null, replayed: true }),
      version: (state) => state.version,
    };
    const storage = new FakeTransactionalStorage();
    const kernel = new TransactionalAggregateKernel(stateWith(storage), adapter);

    await expect(
      kernel.initialize({
        version: 0,
        payload: new Uint8Array(5 * 1_048_576),
      }),
    ).rejects.toMatchObject({ code: "INVALID_AGGREGATE_OUTPUT" });
    expect(storage.values.size).toBe(0);
  }, 30_000);

  it("preserves the aggregate depth-64 contract inside the storage record wrapper", async () => {
    interface State {
      readonly version: number;
      readonly payload: Record<string, unknown>;
    }
    const adapter: AggregateAdapter<State, State, null, null> = {
      kind: "record-depth-headroom-test",
      create: (input) => input,
      validate: (state) => {
        encodeCanonicalCbor(state, { maxDepth: 64 });
      },
      apply: async (state) => ({ state, outcome: null, replayed: true }),
      version: (state) => state.version,
    };
    const payload: Record<string, unknown> = {};
    let cursor = payload;
    for (let depth = 0; depth < 63; depth += 1) {
      const next: Record<string, unknown> = {};
      cursor.next = next;
      cursor = next;
    }
    const storage = new FakeTransactionalStorage();
    const kernel = new TransactionalAggregateKernel(stateWith(storage), adapter);

    await expect(kernel.initialize({ version: 0, payload })).resolves.toEqual({
      version: 0,
      replayed: false,
    });
    await expect(kernel.query(null, (state) => state)).resolves.toEqual({
      version: 0,
      payload,
    });
  });

  it("does not expose aliased outcomes or return before commit", async () => {
    const storage = new FakeTransactionalStorage();
    const cell = userCell(storage);
    await cell.initializeUser(userInitialization());

    const gate = storage.blockNextCommit();
    let settled = false;
    const pending = cell.executeUserCommand(userCommand()).finally(() => {
      settled = true;
    });
    await gate.reached;
    expect(settled).toBe(false);
    gate.release();
    const committed = await pending;
    (committed.outcome as { kind: string }).kind = "tampered";

    const replayed = await cell.executeUserCommand(userCommand());
    expect(replayed.outcome).toEqual({ kind: "preferences_replaced", revision: 1 });
  });

  it("enforces structured-clone inputs and detects stored corruption", async () => {
    const storage = new FakeTransactionalStorage();
    const cell = userCell(storage);
    await cell.initializeUser(userInitialization());
    const attemptsBefore = storage.callbackAttempts;

    await expect(
      cell.executeUserCommand({ ...userCommand(), uncloneable: () => undefined } as never),
    ).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
    await expect(
      cell.executeUserCommand({ ...userCommand(), uncloneable: () => undefined } as never),
    ).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
    expect(storage.callbackAttempts).toBe(attemptsBefore);

    storage.corruptState((state) => {
      state.schemaVersion = 999;
    });
    await expect(
      cell.readUser(userAuthority({ permissions: ["user.read"] }), 20),
    ).rejects.toMatchObject({ code: "CORRUPT_STATE" });
  });
});

describe("named aggregate cells", () => {
  it("exports current Durable Object RPC endpoint classes", () => {
    for (const Cell of [
      SessionCell,
      WorkspaceCell,
      UserCell,
      ExtensionStateCell,
      CapabilityGenerationCell,
      AuditCell,
    ]) {
      expect(DurableObject.prototype.isPrototypeOf(Cell.prototype)).toBe(true);
    }
  });

  it("exposes only versioned operation envelopes at the Durable Object RPC boundary", async () => {
    const rawStorage = new FakeTransactionalStorage();
    const rawResponse = await rawUserCell(rawStorage).initializeUser(
      userInitialization() as never,
    );
    expect(rawResponse).toMatchObject({
      protocol: PROTOCOL_NAME,
      major: PROTOCOL_MAJOR,
      minor: PROTOCOL_MINOR,
      schemaDigest: HOST_RPC_CONTRACTS["user.initialize"].schemaDigest,
      requestId: "invalid-request",
      payload: { ok: false, error: { code: "INVALID_ARGUMENT" } },
    });
    expect(rawStorage.values.size).toBe(0);

    const storage = new FakeTransactionalStorage();
    const response = await rawUserCell(storage).initializeUser(
      hostRpcRequest("user.initialize", userInitialization(), "request-user-init") as never,
    );
    expect(response).toMatchObject({
      protocol: PROTOCOL_NAME,
      major: PROTOCOL_MAJOR,
      minor: PROTOCOL_MINOR,
      schemaDigest: HOST_RPC_CONTRACTS["user.initialize"].schemaDigest,
      requestId: "request-user-init",
      payload: {
        ok: true,
        result: { version: 0, replayed: false },
      },
    });
  });

  it("classifies schema-valid envelopes with invalid typed payloads before mutation", async () => {
    const storage = new FakeTransactionalStorage();
    const initialization = {
      ...sessionInitialization(),
      runtimeRevisionDigest: "not-a-digest",
    };
    const route = routedCellContext(
      storage,
      "SESSION_CELL",
      sessionCellName(initialization.tenantId, initialization.sessionId),
    );
    const cell = new SessionCell(route.state, route.environment);

    const response = await cell.initializeSession(
      hostRpcRequest("session.initialize", initialization),
    );

    expect(response.payload).toEqual({
      ok: false,
      error: {
        code: "INVALID_ARGUMENT",
        message: "The RPC request is invalid.",
      },
    });
    expect(storage.values.size).toBe(0);
  });

  it("rejects a second physical cell routed to the same logical aggregate identity", async () => {
    const expectedPhysicalId = {
      equals: (other: unknown) => other === expectedPhysicalId,
      toString: () => "physical-user-cell-expected",
    };
    const misroutedPhysicalId = {
      equals: (other: unknown) => other === misroutedPhysicalId,
      toString: () => "physical-user-cell-misrouted",
    };
    const logicalName = userCellName("tenant-1", "user-1");
    const namespace = {
      idFromName: (name: string) => {
        if (name !== logicalName) {
          throw new Error("unexpected logical cell name");
        }
        return expectedPhysicalId;
      },
    };
    const environment = { USER_CELL: namespace };
    const authoritativeStorage = new FakeTransactionalStorage();
    const authoritative = new UserCell({
      id: expectedPhysicalId,
      storage: authoritativeStorage,
    } as never, environment);
    await expect(hostRpcResult(
      "user.initialize",
      userInitialization(),
      (request) => authoritative.initializeUser(request),
    )).resolves.toMatchObject({ replayed: false });

    const misroutedStorage = new FakeTransactionalStorage();
    const misrouted = new UserCell({
      id: misroutedPhysicalId,
      storage: misroutedStorage,
    } as never, environment);
    await expect(hostRpcResult(
      "user.initialize",
      userInitialization(),
      (request) => misrouted.initializeUser(request),
    )).rejects.toMatchObject({ code: "CELL_ID_MISMATCH" });
    expect(misroutedStorage.values.size).toBe(0);
  });

  it("routes Session commands only through the Session aggregate", async () => {
    const storage = new FakeTransactionalStorage();
    const route = routedCellContext(
      storage,
      "SESSION_CELL",
      sessionCellName("tenant-1", "session-1"),
    );
    const cell = new SessionCell(route.state, route.environment);
    await hostRpcResult(
      "session.initialize",
      sessionInitialization(),
      (request) => cell.initializeSession(request),
    );
    const command = await enqueueSessionCommand();

    const committed = await hostRpcResult(
      "session.execute",
      command,
      (request) => cell.executeSessionCommand(request),
    );
    const replayed = await hostRpcResult(
      "session.execute",
      command,
      (request) => cell.executeSessionCommand(request),
    );
    expect(committed).toMatchObject({ version: 1, replayed: false });
    expect(replayed).toMatchObject({ version: 1, replayed: true });
    expect(replayed.outcome).toEqual(committed.outcome);
    expect(storage.values.size).toBe(3);
    const snapshot = await hostRpcResult(
      "session.read",
      { authority: sessionAuthority(), now: 200 },
      (request) => cell.readSession(request),
    );
    expect(snapshot).toMatchObject({
      tenantId: "tenant-1",
      sessionId: "session-1",
      authorizationGeneration: 6,
      eventSequence: 1,
      activeTurn: { turnId: "turn-1" },
      queuedTurns: [],
    });
    expect("load" in cell || "save" in cell || "patch" in cell).toBe(false);
  });

  it("fails closed when a Session read authority is forged, expired, or stale", async () => {
    const storage = new FakeTransactionalStorage();
    const route = routedCellContext(
      storage,
      "SESSION_CELL",
      sessionCellName("tenant-1", "session-1"),
    );
    const cell = new SessionCell(route.state, route.environment);
    await hostRpcResult(
      "session.initialize",
      sessionInitialization(),
      (request) => cell.initializeSession(request),
    );

    const invalidAuthorities = [
      sessionAuthority({ tenantId: "tenant-2" }),
      sessionAuthority({ subjectId: "session-2" }),
      sessionAuthority({ expiresAt: 200 }),
      sessionAuthority({
        authorizationGeneration: 5,
        currentAuthorizationGeneration: 5,
      }),
    ];
    for (const authority of invalidAuthorities) {
      await expect(hostRpcResult(
        "session.read",
        { authority, now: 200 },
        (request) => cell.readSession(request),
      )).rejects.toMatchObject({
        code: expect.stringMatching(/^(?:PERMISSION_DENIED|STALE_GENERATION)$/),
      });
    }
  });

  it("routes Workspace commands and only exposes its authorized invocation lookup", async () => {
    const storage = new FakeTransactionalStorage();
    const route = routedCellContext(
      storage,
      "WORKSPACE_CELL",
      workspaceCellName("tenant-1", "workspace-1"),
    );
    const cell = new WorkspaceCell(route.state, route.environment);
    await hostRpcResult(
      "workspace.initialize",
      workspaceInitialization(),
      (request) => cell.initializeWorkspace(request),
    );
    const command = acquireWorkspaceCommand();

    const committed = await hostRpcResult(
      "workspace.execute",
      command,
      (request) => cell.executeWorkspaceCommand(request),
    );
    const replayed = await hostRpcResult(
      "workspace.execute",
      command,
      (request) => cell.executeWorkspaceCommand(request),
    );
    expect(committed).toMatchObject({ version: 1, replayed: false });
    expect(replayed).toMatchObject({ version: 1, replayed: true });
    expect(committed.outcome.kind).toBe("write_lease_acquired");
    await expect(hostRpcResult(
      "workspace.lookup-invocation",
      {
        invocationId: "invocation-workspace-1",
        requestDigest: digest("6"),
        authority: workspaceAuthority({ purpose: "settlement" }),
        now: 101,
      },
      (request) => cell.lookupWorkspaceInvocation(request),
    )).resolves.toBeNull();
    expect("readWorkspace" in cell).toBe(false);
  });

  it("routes ExtensionState commands through its authorized read model", async () => {
    const storage = new FakeTransactionalStorage();
    const initialization = extensionInitialization();
    const route = routedCellContext(
      storage,
      "EXTENSION_STATE_CELL",
      extensionStateCellName(initialization),
    );
    const cell = new ExtensionStateCell(route.state, route.environment);
    await hostRpcResult(
      "extension-state.initialize",
      initialization,
      (request) => cell.initializeExtensionState(request),
    );
    const command: ExtensionStateCommand = {
      kind: "replace_extension_state",
      commandId: "extension-replace-1",
      expectedRevision: 0,
      now: 10,
      authority: extensionAuthority(["extension-state.write"]),
      value: { outputFormat: "svg" },
    };

    await expect(hostRpcResult(
      "extension-state.execute",
      command,
      (request) => cell.executeExtensionStateCommand(request),
    )).resolves.toMatchObject({
      version: 1,
      replayed: false,
      outcome: { kind: "extension_state_replaced", revision: 1 },
    });
    const snapshot = await hostRpcResult(
      "extension-state.read",
      { authority: extensionAuthority(["extension-state.read"]), now: 11 },
      (request) => cell.readExtensionState(request),
    );
    expect(snapshot.value).toEqual({ outputFormat: "svg" });
    await expect(
      hostRpcResult(
        "extension-state.read",
        { authority: extensionAuthority([]), now: 11 },
        (request) => cell.readExtensionState(request),
      ),
    ).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
  });

  it("routes CapabilityGeneration commands and exposes only the authorized assertion", async () => {
    const storage = new FakeTransactionalStorage();
    const initialization = generationInitialization();
    const route = routedCellContext(
      storage,
      "CAPABILITY_GENERATION_CELL",
      capabilityGenerationCellName(initialization),
    );
    const cell = new CapabilityGenerationCell(route.state, route.environment);
    await hostRpcResult(
      "capability-generation.initialize",
      initialization,
      (request) => cell.initializeCapabilityGeneration(request),
    );
    const authority = extensionAuthority(["generation.read", "generation.rotate"]);

    await expect(hostRpcResult(
      "capability-generation.execute",
      {
        kind: "rotate_capability_generation",
        commandId: "generation-rotate-1",
        expectedRevision: 0,
        now: 10,
        authority,
        nextGeneration: 8,
        reason: "operator-rotation",
      },
      (request) => cell.executeCapabilityGenerationCommand(request),
    )).resolves.toMatchObject({
      version: 1,
      outcome: {
        kind: "capability_generation_rotated",
        generation: 8,
      },
    });
    await expect(
      hostRpcResult(
        "capability-generation.assert-current",
        { candidateGeneration: 8, authority, now: 11 },
        (request) => cell.assertCurrentCapabilityGeneration(request),
      ),
    ).resolves.toEqual({ current: true, version: 1 });
    await expect(
      hostRpcResult(
        "capability-generation.assert-current",
        { candidateGeneration: 7, authority, now: 11 },
        (request) => cell.assertCurrentCapabilityGeneration(request),
      ),
    ).rejects.toMatchObject({ code: "STALE_GENERATION" });
  });

  it("routes Audit commands and reads only through the aggregate ACL", async () => {
    const storage = new FakeTransactionalStorage();
    const route = routedCellContext(
      storage,
      "AUDIT_CELL",
      auditCellName("tenant-1"),
    );
    const cell = new AuditCell(route.state, route.environment);
    await hostRpcResult(
      "audit.initialize",
      auditInitialization(),
      (request) => cell.initializeAudit(request),
    );
    await expect(hostRpcResult(
      "audit.execute",
      {
        kind: "append_audit_event",
        commandId: "audit-append-1",
        expectedSequence: 0,
        now: 100,
        authority: auditAuthority(),
        event: auditEvent(),
      },
      (request) => cell.executeAuditCommand(request),
    )).resolves.toMatchObject({
      version: 1,
      replayed: false,
      outcome: { kind: "audit_event_appended", sequence: 1 },
    });
    const entries = await hostRpcResult(
      "audit.read",
      {
        afterSequence: 0,
        limit: 10,
        authority: auditAuthority(["audit.read"]),
        now: 101,
      },
      (request) => cell.readAuditEntries(request),
    );
    expect(entries).toHaveLength(1);
    entries[0]!.event.metadata = { tampered: true };
    const reread = await hostRpcResult(
      "audit.read",
      {
        afterSequence: 0,
        limit: 10,
        authority: auditAuthority(["audit.read"]),
        now: 101,
      },
      (request) => cell.readAuditEntries(request),
    );
    expect(reread[0]!.event.metadata).toEqual({ source: "host-test" });
  });

  it("bounds Audit append and paginated-read storage I/O independently of log length", async () => {
    const storage = new FakeTransactionalStorage();
    const route = routedCellContext(
      storage,
      "AUDIT_CELL",
      auditCellName("tenant-1"),
    );
    const cell = new AuditCell(route.state, route.environment);
    await hostRpcResult(
      "audit.initialize",
      auditInitialization(),
      (request) => cell.initializeAudit(request),
    );

    const append = (expectedSequence: number) => hostRpcResult(
      "audit.execute",
      {
        kind: "append_audit_event" as const,
        commandId: `audit-bounded-${expectedSequence}`,
        expectedSequence,
        now: 100 + expectedSequence,
        authority: auditAuthority(),
        event: {
          ...auditEvent(),
          timestamp: 100 + expectedSequence,
          correlation: {
            ...auditEvent().correlation,
            invocationId: `audit-bounded-invocation-${expectedSequence}`,
          },
          metadata: { source: "host-test", padding: "x".repeat(2_048) },
        },
      },
      (request) => cell.executeAuditCommand(request),
    );
    const readOne = () => hostRpcResult(
      "audit.read",
      {
        afterSequence: 0,
        limit: 1,
        authority: auditAuthority(["audit.read"]),
        now: 1_000,
      },
      (request) => cell.readAuditEntries(request),
    );

    await append(0);
    await append(1);
    storage.resetObservedIo();
    await append(2);
    const shortAppendIo = storage.observedIoBytes();
    storage.resetObservedIo();
    await readOne();
    const shortReadIo = storage.observedIoBytes();

    for (let sequence = 3; sequence < 24; sequence += 1) {
      await append(sequence);
    }
    storage.resetObservedIo();
    await append(24);
    const longAppendIo = storage.observedIoBytes();
    storage.resetObservedIo();
    await readOne();
    const longReadIo = storage.observedIoBytes();

    expect(longAppendIo).toBeLessThanOrEqual(shortAppendIo * 2);
    expect(longReadIo).toBeLessThanOrEqual(shortReadIo * 2);
    expect(
      [...storage.values.keys()].filter((key) => key.includes(".audit.v1.entry.")),
    ).toHaveLength(25);
  });

  it("keeps Audit replay and CAS outcomes atomic across transaction retries", async () => {
    const storage = new FakeTransactionalStorage();
    const route = routedCellContext(
      storage,
      "AUDIT_CELL",
      auditCellName("tenant-1"),
    );
    const cell = new AuditCell(route.state, route.environment);
    await hostRpcResult(
      "audit.initialize",
      auditInitialization(),
      (request) => cell.initializeAudit(request),
    );
    const command = {
      kind: "append_audit_event" as const,
      commandId: "audit-atomic-1",
      expectedSequence: 0,
      now: 100,
      authority: auditAuthority(),
      event: auditEvent(),
    };
    storage.forceRetryCount = 1;
    const duplicateResults = await Promise.all([
      hostRpcResult(
        "audit.execute",
        command,
        (request) => cell.executeAuditCommand(request),
      ),
      hostRpcResult(
        "audit.execute",
        structuredClone(command),
        (request) => cell.executeAuditCommand(request),
      ),
    ]);
    expect(duplicateResults.map((result) => result.replayed).sort()).toEqual([
      false,
      true,
    ]);
    expect(duplicateResults.every((result) => result.version === 1)).toBe(true);

    const contenders = await Promise.allSettled([
      hostRpcResult(
        "audit.execute",
        {
          ...command,
          commandId: "audit-contender-a",
          expectedSequence: 1,
          now: 101,
          event: {
            ...auditEvent(),
            timestamp: 101,
            eventType: "host.contender-a",
          },
        },
        (request) => cell.executeAuditCommand(request),
      ),
      hostRpcResult(
        "audit.execute",
        {
          ...command,
          commandId: "audit-contender-b",
          expectedSequence: 1,
          now: 101,
          event: {
            ...auditEvent(),
            timestamp: 101,
            eventType: "host.contender-b",
          },
        },
        (request) => cell.executeAuditCommand(request),
      ),
    ]);
    expect(contenders.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(contenders.find((result) => result.status === "rejected")).toMatchObject({
      status: "rejected",
      reason: expect.objectContaining({ code: "CONFLICT" }),
    });

    const replay = await hostRpcResult(
      "audit.execute",
      command,
      (request) => cell.executeAuditCommand(request),
    );
    expect(replay).toMatchObject({ version: 2, replayed: true });
    const entries = await hostRpcResult(
      "audit.read",
      {
        afterSequence: 0,
        limit: 10,
        authority: auditAuthority(["audit.read"]),
        now: 102,
      },
      (request) => cell.readAuditEntries(request),
    );
    expect(entries).toHaveLength(2);
  });

  it("fails closed when a normalized Audit chain-edge record is corrupt", async () => {
    const storage = new FakeTransactionalStorage();
    const route = routedCellContext(
      storage,
      "AUDIT_CELL",
      auditCellName("tenant-1"),
    );
    const cell = new AuditCell(route.state, route.environment);
    await hostRpcResult(
      "audit.initialize",
      auditInitialization(),
      (request) => cell.initializeAudit(request),
    );
    await hostRpcResult(
      "audit.execute",
      {
        kind: "append_audit_event",
        commandId: "audit-corruption-1",
        expectedSequence: 0,
        now: 100,
        authority: auditAuthority(),
        event: auditEvent(),
      },
      (request) => cell.executeAuditCommand(request),
    );
    const entryKey = [...storage.values.keys()].find((key) =>
      key.includes(".audit.v1.entry."));
    expect(entryKey).toBeDefined();
    const corrupted = structuredClone(storage.values.get(entryKey!)) as {
      entry: unknown;
    };
    corrupted.entry = null;
    storage.values.set(entryKey!, corrupted);
    storage.revision += 1;

    await expect(hostRpcResult(
      "audit.read",
      {
        afterSequence: 0,
        limit: 1,
        authority: auditAuthority(["audit.read"]),
        now: 101,
      },
      (request) => cell.readAuditEntries(request),
    )).rejects.toMatchObject({ code: "CORRUPT_STATE" });
  });

  it("does not recreate a normalized Audit genesis after either header is lost", async () => {
    for (const lostSuffix of [".audit.v1.head", ".audit.v1.anchor"]) {
      const storage = new FakeTransactionalStorage();
      const route = routedCellContext(
        storage,
        "AUDIT_CELL",
        auditCellName("tenant-1"),
      );
      const cell = new AuditCell(route.state, route.environment);
      await hostRpcResult(
        "audit.initialize",
        auditInitialization(),
        (request) => cell.initializeAudit(request),
      );
      await hostRpcResult(
        "audit.execute",
        {
          kind: "append_audit_event",
          commandId: `audit-header-loss-${lostSuffix}`,
          expectedSequence: 0,
          now: 100,
          authority: auditAuthority(),
          event: auditEvent(),
        },
        (request) => cell.executeAuditCommand(request),
      );
      const lostKey = [...storage.values.keys()].find((key) =>
        key.endsWith(lostSuffix));
      expect(lostKey).toBeDefined();
      storage.values.delete(lostKey!);
      storage.revision += 1;

      await expect(hostRpcResult(
        "audit.initialize",
        auditInitialization(),
        (request) => cell.initializeAudit(request),
      )).rejects.toMatchObject({ code: "CORRUPT_STATE" });
      expect(storage.values.has(lostKey!)).toBe(false);
    }
  });

  it("fails closed when either normalized Audit command index copy is lost", async () => {
    for (const keyFragment of [
      ".audit.v1.command.",
      ".audit.v1.command-copy.",
    ]) {
      const storage = new FakeTransactionalStorage();
      const route = routedCellContext(
        storage,
        "AUDIT_CELL",
        auditCellName("tenant-1"),
      );
      const cell = new AuditCell(route.state, route.environment);
      await hostRpcResult(
        "audit.initialize",
        auditInitialization(),
        (request) => cell.initializeAudit(request),
      );
      const command = {
        kind: "append_audit_event" as const,
        commandId: "audit-index-loss-1",
        expectedSequence: 0,
        now: 100,
        authority: auditAuthority(),
        event: auditEvent(),
      };
      await hostRpcResult(
        "audit.execute",
        command,
        (request) => cell.executeAuditCommand(request),
      );
      const indexKey = [...storage.values.keys()].find((key) =>
        key.includes(keyFragment));
      expect(indexKey).toBeDefined();
      storage.values.delete(indexKey!);
      storage.revision += 1;

      await expect(hostRpcResult(
        "audit.execute",
        command,
        (request) => cell.executeAuditCommand(request),
      )).rejects.toMatchObject({ code: "CORRUPT_STATE" });
    }
  });

  it("binds normalized Audit storage to its deterministic physical cell", async () => {
    const expectedPhysicalId = {
      equals: (other: unknown) => other === expectedPhysicalId,
      toString: () => "physical-audit-cell-expected",
    };
    const misroutedPhysicalId = {
      equals: (other: unknown) => other === misroutedPhysicalId,
      toString: () => "physical-audit-cell-misrouted",
    };
    const logicalName = auditCellName("tenant-1");
    const environment = {
      AUDIT_CELL: {
        idFromName: (name: string) => {
          if (name !== logicalName) {
            throw new Error("unexpected logical cell name");
          }
          return expectedPhysicalId;
        },
      },
    };
    const authoritativeStorage = new FakeTransactionalStorage();
    const authoritative = new AuditCell({
      id: expectedPhysicalId,
      storage: authoritativeStorage,
    } as never, environment);
    await expect(hostRpcResult(
      "audit.initialize",
      auditInitialization(),
      (request) => authoritative.initializeAudit(request),
    )).resolves.toEqual({ version: 0, replayed: false });

    const misroutedStorage = new FakeTransactionalStorage();
    const misrouted = new AuditCell({
      id: misroutedPhysicalId,
      storage: misroutedStorage,
    } as never, environment);
    await expect(hostRpcResult(
      "audit.initialize",
      auditInitialization(),
      (request) => misrouted.initializeAudit(request),
    )).rejects.toMatchObject({ code: "CELL_ID_MISMATCH" });
    expect(misroutedStorage.values.size).toBe(0);
  });

  it("preserves the aggregate item budget without rewriting prior Audit entries", async () => {
    const storage = new FakeTransactionalStorage();
    const route = routedCellContext(
      storage,
      "AUDIT_CELL",
      auditCellName("tenant-1"),
    );
    const cell = new AuditCell(route.state, route.environment);
    await hostRpcResult(
      "audit.initialize",
      auditInitialization(),
      (request) => cell.initializeAudit(request),
    );
    const metadata = { items: Array.from({ length: 50_000 }, () => null) };
    await expect(hostRpcResult(
      "audit.execute",
      {
        kind: "append_audit_event",
        commandId: "audit-item-budget-1",
        expectedSequence: 0,
        now: 100,
        authority: auditAuthority(),
        event: { ...auditEvent(), metadata },
      },
      (request) => cell.executeAuditCommand(request),
    )).resolves.toMatchObject({ version: 1, replayed: false });
    await expect(hostRpcResult(
      "audit.execute",
      {
        kind: "append_audit_event",
        commandId: "audit-item-budget-2",
        expectedSequence: 1,
        now: 101,
        authority: auditAuthority(),
        event: { ...auditEvent(), timestamp: 101, metadata },
      },
      (request) => cell.executeAuditCommand(request),
    )).rejects.toMatchObject({ code: "INVALID_AGGREGATE_OUTPUT" });
    await expect(hostRpcResult(
      "audit.read",
      {
        afterSequence: 0,
        limit: 10,
        authority: auditAuthority(["audit.read"]),
        now: 102,
      },
      (request) => cell.readAuditEntries(request),
    )).resolves.toHaveLength(1);
  });

  it("constructs collision-free deterministic names for every aggregate identity", () => {
    expect(workspaceCellName("tenant-1", "workspace-1")).toContain("workspace");
    expect(extensionStateCellName(extensionInitialization())).toContain("extension-state");
    expect(capabilityGenerationCellName(generationInitialization())).toContain(
      "capability-generation",
    );
    expect(auditCellName("tenant-1")).toContain("audit");
    const names = new Set([
      sessionCellName("tenant-1", "shared"),
      workspaceCellName("tenant-1", "shared"),
      userCellName("tenant-1", "shared"),
      auditCellName("shared"),
    ]);
    expect(names.size).toBe(4);
  });
});
