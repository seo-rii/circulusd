import { describe, expect, it } from "vitest";

import {
  PROTOCOL_MAJOR,
  PROTOCOL_MINOR,
  PROTOCOL_NAME,
  type Digest,
} from "@circulusd/protocol-types";

import { WorkspaceCell, workspaceCellName } from "../src/host/index.ts";
import {
  HOST_RPC_CONTRACTS,
  type HostRpcOperation,
  type HostRpcResponse,
} from "../src/host/rpc.ts";
import { ChunkedAggregateStorage } from "../src/host/storage.ts";
import {
  assertWorkspaceInvariants,
  type WorkspaceAggregateState,
  type WorkspaceAuthoritySnapshot,
  type WorkspaceCommand,
  type WorkspaceLeaseFence,
  type WorkspaceWriteLease,
} from "../src/workspace/index.ts";
import { RestartableDurableStorage } from "./support/restartable-durable-storage.ts";

const digest = (character: string): Digest => `sha256:${character.repeat(64)}`;

function authority(invocationId = "invocation-1"): WorkspaceAuthoritySnapshot {
  return {
    purpose: "admission",
    serviceBinding: "workspace",
    tenantId: "tenant-1",
    userId: "user-1",
    sessionId: `session-${invocationId}`,
    workspaceId: "workspace-1",
    turnId: `turn-${invocationId}`,
    runtimeRevision: "runtime-1",
    policySnapshotDigest: digest("a"),
    emergencyOverlayDigest: digest("b"),
    effectivePermissions: ["workspace.read", "workspace.write"],
    sessionStatus: "active",
    turnStatus: "active",
    turnLeaseActive: true,
    turnLeaseExpiresAt: 20_000,
    effectStatus: "dispatched",
    effectService: "workspace",
    effectOperation: "workspace.commit",
    effectId: `effect-${invocationId}`,
    invocationId,
    requestDigest: digest(invocationId === "invocation-1" ? "c" : "d"),
    replayPolicy: "idempotency-key",
    dispatchAttempt: 1,
    turnLeaseGeneration: 1,
    placementGeneration: 1,
    sandboxGeneration: 1,
    sandboxId: `sandbox-${invocationId}`,
    backend: "nsjail",
    authorizationGeneration: 1,
    issuedAt: 0,
    expiresAt: 10_000,
  };
}

function fence(lease: WorkspaceWriteLease): WorkspaceLeaseFence {
  return {
    leaseId: lease.leaseId,
    invocationId: lease.invocationId,
    requestDigest: lease.requestDigest,
    effectId: lease.effectId,
    sessionId: lease.sessionId,
    sandboxId: lease.sandboxId,
    leaseGeneration: lease.leaseGeneration,
    dispatchAttempt: lease.dispatchAttempt,
    turnLeaseGeneration: lease.turnLeaseGeneration,
    placementGeneration: lease.placementGeneration,
    sandboxGeneration: lease.sandboxGeneration,
    projectionGeneration: lease.projectionGeneration,
    authorizationGeneration: lease.authorizationGeneration,
  };
}

function envelope(operation: HostRpcOperation, payload: unknown) {
  return {
    protocol: PROTOCOL_NAME,
    major: PROTOCOL_MAJOR,
    minor: PROTOCOL_MINOR,
    schemaDigest: HOST_RPC_CONTRACTS[operation].schemaDigest,
    requestId: "workspace-clock-request",
    payload,
  };
}

function result<Value>(response: HostRpcResponse<Value>): Value {
  if (!response.payload.ok) {
    throw Object.assign(new Error(response.payload.error.message), {
      code: response.payload.error.code,
    });
  }
  return response.payload.result;
}

async function preparedWorkspace() {
  let now = 100;
  let storage = new RestartableDurableStorage();
  const physicalId = (name: string) => ({
    toString: () => name,
    equals: (other: unknown) => String(other) === name,
  });
  const create = () => new WorkspaceCell(
    { storage, id: physicalId(workspaceCellName("tenant-1", "workspace-1")) } as never,
    { WORKSPACE_CELL: { idFromName: physicalId } } as never,
    () => now,
  );
  let cell = create();
  result(await cell.initializeWorkspace(envelope("workspace.initialize", {
    workspaceId: "workspace-1",
    tenantId: "tenant-1",
    initialRootDigest: digest("0"),
  })));
  const execute = async (command: WorkspaceCommand) =>
    result(await cell.executeWorkspaceCommand(envelope("workspace.execute", command)));
  const admission = authority();
  const acquired = await execute({
    kind: "acquire_write_lease",
    expectedEventSequence: 0,
    now: 100,
    authority: admission,
    requestedLeaseId: "lease-1",
    sandboxId: admission.sandboxId,
    backend: admission.backend,
    projectionGeneration: 1,
    requestedLeaseTtlMs: 200,
    requestedMaximumHoldMs: 500,
    acquireDeadline: 1_000,
    waitPolicy: "queue",
  });
  if (acquired.outcome.kind !== "write_lease_acquired") {
    throw new Error("expected Workspace lease");
  }
  const lease = acquired.outcome.lease;
  const leaseFence = fence(lease);
  now = 120;
  await execute({
    kind: "prepare_materialization",
    expectedEventSequence: 1,
    now: 120,
    ticketId: "ticket-1",
    accessMode: "read_write",
    requestedRevision: 0,
    authority: admission,
    sandboxId: admission.sandboxId,
    backend: admission.backend,
    projectionGeneration: 1,
    leaseFence,
    ticketTtlMs: 500,
  });
  const commit = (embeddedNow: number): Extract<WorkspaceCommand, { kind: "commit_workspace" }> => ({
    kind: "commit_workspace",
    expectedEventSequence: 2,
    now: embeddedNow,
    materializationTicketId: "ticket-1",
    leaseFence,
    baseRevision: 0,
    workspaceCommitId: "commit-1",
    postExecutionRootDigest: digest("1"),
    referencedObjectDigests: [digest("1")],
    protectionProofs: [{
      permitId: "permit-1",
      tenantId: "tenant-1",
      objectDigest: digest("1"),
      guardGeneration: 1,
      status: "protected",
    }],
    authority: { ...admission, purpose: "settlement" },
  });
  const records = new ChunkedAggregateStorage<WorkspaceAggregateState>(
    "workspace",
    assertWorkspaceInvariants,
    {
      currentId: physicalId(workspaceCellName("tenant-1", "workspace-1")),
      namespace: { idFromName: physicalId },
    },
  );
  return {
    execute,
    commit,
    lease,
    get storage() { return storage; },
    setClock(value: number) { now = value; },
    restart() { storage = storage.restart(); cell = create(); },
    async readState() {
      return storage.transaction(async (transaction) => {
        const stored = await records.read(transaction);
        if (stored === undefined) throw new Error("expected stored Workspace");
        return stored.record.state;
      });
    },
  };
}

describe("Workspace commit trusted transaction clock", () => {
  it.each([300, 5_000])("rejects a fresh backdated commit at host time %i after cold restart", async (hostNow) => {
    const workspace = await preparedWorkspace();
    const original = await workspace.readState();
    const durableRevision = workspace.storage.durableRevision;
    expect(workspace.lease.expiresAt).toBe(300);
    workspace.setClock(hostNow);
    workspace.restart();

    await expect(workspace.execute(workspace.commit(130)))
      .rejects.toMatchObject({ code: "LEASE_EXPIRED" });
    expect(workspace.storage.durableRevision).toBe(durableRevision);
    expect(await workspace.readState()).toEqual(original);
  });

  it.each([[250, 130], [130, 50_000]])("commits at live host time %i despite caller time %i", async (hostNow, embeddedNow) => {
    const workspace = await preparedWorkspace();
    workspace.setClock(hostNow);
    workspace.restart();

    const committed = await workspace.execute(workspace.commit(embeddedNow));
    expect(committed).toMatchObject({
      version: 3,
      replayed: false,
      outcome: { kind: "workspace_committed", result: { revision: 1 } },
    });
    expect((await workspace.readState()).revisions[1]?.committedAt).toBe(hostNow);
  });

  it("validates fresh settlement authority against host time", async () => {
    const workspace = await preparedWorkspace();
    workspace.setClock(250);
    workspace.restart();
    const command = workspace.commit(130);
    const durableRevision = workspace.storage.durableRevision;

    await expect(workspace.execute({
      ...command,
      authority: { ...command.authority, turnLeaseExpiresAt: 200 },
    })).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
    expect(workspace.storage.durableRevision).toBe(durableRevision);
  });

  it("reaps expired queued acquire deadlines using the fresh commit host time", async () => {
    const workspace = await preparedWorkspace();
    const waiter = authority("invocation-2");
    workspace.setClock(121);
    const queued = await workspace.execute({
      kind: "acquire_write_lease",
      expectedEventSequence: 2,
      now: 121,
      authority: waiter,
      requestedLeaseId: "lease-2",
      sandboxId: waiter.sandboxId,
      backend: waiter.backend,
      projectionGeneration: 1,
      requestedLeaseTtlMs: 200,
      requestedMaximumHoldMs: 500,
      acquireDeadline: 200,
      waitPolicy: "queue",
    });
    expect(queued.outcome.kind).toBe("write_lease_queued");
    workspace.setClock(250);
    workspace.restart();

    await workspace.execute({ ...workspace.commit(130), expectedEventSequence: 3 });
    const stored = await workspace.readState();
    expect(stored.writeQueue).toEqual([]);
    expect(stored.leaseHistory.find((entry) => entry.invocationId === waiter.invocationId))
      .toMatchObject({ status: "timed_out" });
  });

  it.each([[130, 0], [50_000, 0], [0, 100]])("replays a committed ledger with caller time %i and authority issued at %i after lease expiry", async (embeddedNow, issuedAt) => {
    const workspace = await preparedWorkspace();
    workspace.setClock(130);
    const base = workspace.commit(embeddedNow);
    const command = { ...base, authority: { ...base.authority, issuedAt } };
    const committed = await workspace.execute(command);
    const original = await workspace.readState();
    expect(original.revisions[1]?.committedAt).toBe(130);
    const durableRevision = workspace.storage.durableRevision;
    workspace.setClock(50_000);
    workspace.restart();

    const replayed = await workspace.execute(command);
    expect(replayed).toEqual({ ...committed, replayed: true });
    expect(workspace.storage.durableRevision).toBe(durableRevision);
    expect(await workspace.readState()).toEqual(original);
    await expect(workspace.execute({ ...command, workspaceCommitId: "commit-2" }))
      .rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
    expect(workspace.storage.durableRevision).toBe(durableRevision);
  });

  it.each([130, 500, 50_000])("replays with renewed recovery authority at host time despite caller time %i", async (embeddedNow) => {
    const workspace = await preparedWorkspace();
    workspace.setClock(130);
    const command = workspace.commit(130);
    const committed = await workspace.execute(command);
    const original = await workspace.readState();
    const durableRevision = workspace.storage.durableRevision;
    workspace.setClock(500);
    workspace.restart();

    const replayed = await workspace.execute({
      ...command,
      now: embeddedNow,
      authority: {
        ...command.authority,
        issuedAt: 400,
        expiresAt: 1_000,
        turnLeaseExpiresAt: 2_000,
        turnLeaseGeneration: command.authority.turnLeaseGeneration + 1,
        placementGeneration: command.authority.placementGeneration + 1,
        authorizationGeneration: command.authority.authorizationGeneration + 1,
        effectStatus: "externally_committed",
      },
    });
    expect(replayed).toEqual({ ...committed, replayed: true });
    expect(workspace.storage.durableRevision).toBe(durableRevision);
    expect(await workspace.readState()).toEqual(original);
  });

  it.each([[500, 600], [2_000, 400]])("rejects renewed replay authority invalid at host time %i with issuedAt %i", async (hostNow, issuedAt) => {
    const workspace = await preparedWorkspace();
    workspace.setClock(130);
    const command = workspace.commit(130);
    await workspace.execute(command);
    const durableRevision = workspace.storage.durableRevision;
    workspace.setClock(hostNow);
    workspace.restart();

    await expect(workspace.execute({
      ...command,
      now: 700,
      authority: {
        ...command.authority,
        issuedAt,
        expiresAt: 1_000,
        turnLeaseExpiresAt: 2_000,
        effectStatus: "externally_committed",
      },
    })).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
    expect(workspace.storage.durableRevision).toBe(durableRevision);
  });

  it("retains exact ledger identity and fence checks for renewed replay authority", async () => {
    const workspace = await preparedWorkspace();
    workspace.setClock(130);
    const command = workspace.commit(130);
    await workspace.execute(command);
    const durableRevision = workspace.storage.durableRevision;
    workspace.setClock(500);
    workspace.restart();
    const renewed = {
      ...command,
      now: 500,
      authority: {
        ...command.authority,
        issuedAt: 400,
        expiresAt: 1_000,
        turnLeaseExpiresAt: 2_000,
        effectStatus: "externally_committed" as const,
      },
    };

    await expect(workspace.execute({
      ...renewed,
      authority: { ...renewed.authority, effectId: "different-effect" },
    })).rejects.toMatchObject({ code: "STALE_GENERATION" });
    await expect(workspace.execute({
      ...renewed,
      leaseFence: { ...renewed.leaseFence, leaseGeneration: renewed.leaseFence.leaseGeneration + 1 },
    })).rejects.toMatchObject({ code: "STALE_GENERATION" });
    expect(workspace.storage.durableRevision).toBe(durableRevision);
  });
});
