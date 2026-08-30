import { describe, expect, it } from "vitest";

import {
  digestStructuredValue,
  type Digest,
} from "@circulusd/protocol-types";

import {
  WORKSPACE_COMMAND_SCHEMA_VERSION,
  WORKSPACE_STATE_SCHEMA_VERSION,
  applyWorkspaceCommand,
  assertWorkspaceInvariants,
  createWorkspaceState,
  lookupWorkspaceInvocation,
  type WorkspaceAggregateState,
  type WorkspaceAuthoritySnapshot,
  type WorkspaceLeaseFence,
  type WorkspaceProtectionProof,
  type WorkspaceWriteLease,
} from "../src/workspace/index.ts";

const digest = (character: string): Digest =>
  `sha256:${character.repeat(64)}` as Digest;

type OperationBoundAuthority = WorkspaceAuthoritySnapshot & {
  readonly effectOperation: string;
};

function authority(
  invocationId: string,
  overrides: Partial<OperationBoundAuthority> = {},
): OperationBoundAuthority {
  return {
    purpose: "admission",
    serviceBinding: "workspace",
    tenantId: "tenant-1",
    userId: "user-1",
    sessionId: `session-${invocationId}`,
    workspaceId: "workspace-operation",
    turnId: `turn-${invocationId}`,
    runtimeRevision: "runtime-1",
    policySnapshotDigest: digest("d"),
    emergencyOverlayDigest: digest("e"),
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
    requestDigest: digest("a"),
    replayPolicy: "idempotency-key",
    dispatchAttempt: 1,
    sandboxId: `sandbox-${invocationId}`,
    backend: "nsjail",
    turnLeaseGeneration: 1,
    placementGeneration: 1,
    sandboxGeneration: 1,
    authorizationGeneration: 1,
    issuedAt: 0,
    expiresAt: 10_000,
    ...overrides,
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

async function acquire(
  state: WorkspaceAggregateState,
  invocationId: string,
  now: number,
  overrides: Partial<OperationBoundAuthority> = {},
  waitPolicy: "queue" | "fail" = "queue",
) {
  const currentAuthority = authority(invocationId, {
    workspaceId: state.workspaceId,
    ...overrides,
  });
  const command = {
    kind: "acquire_write_lease" as const,
    expectedEventSequence: state.eventSequence,
    now,
    authority: currentAuthority,
    requestedLeaseId: `lease-${invocationId}-${currentAuthority.dispatchAttempt}`,
    sandboxId: currentAuthority.sandboxId,
    backend: currentAuthority.backend,
    projectionGeneration: currentAuthority.dispatchAttempt,
    requestedLeaseTtlMs: 100,
    requestedMaximumHoldMs: 500,
    acquireDeadline: 1_000,
    waitPolicy,
  };
  return {
    command,
    result: await applyWorkspaceCommand(state, command),
  };
}

async function acquiredLease(
  state: WorkspaceAggregateState,
  invocationId: string,
  now: number,
  overrides: Partial<OperationBoundAuthority> = {},
) {
  const acquired = await acquire(state, invocationId, now, overrides);
  if (acquired.result.outcome.kind !== "write_lease_acquired") {
    throw new Error("expected an acquired lease");
  }
  return {
    ...acquired,
    lease: acquired.result.outcome.lease,
  };
}

async function committedWorkspace() {
  const initial = createWorkspaceState({
    workspaceId: "workspace-operation",
    tenantId: "tenant-1",
    initialRootDigest: digest("0"),
  });
  const acquired = await acquiredLease(initial, "commit", 10);
  const leaseFence = fence(acquired.lease);
  const admissionAuthority = authority("commit");
  const prepared = await applyWorkspaceCommand(acquired.result.state, {
    kind: "prepare_materialization",
    expectedEventSequence: acquired.result.state.eventSequence,
    now: 11,
    ticketId: "ticket-commit",
    accessMode: "read_write",
    requestedRevision: 0,
    authority: admissionAuthority,
    sandboxId: admissionAuthority.sandboxId,
    backend: admissionAuthority.backend,
    projectionGeneration: 1,
    leaseFence,
    ticketTtlMs: 100,
  });
  const settlementAuthority = authority("commit", { purpose: "settlement" });
  const committed = await applyWorkspaceCommand(prepared.state, {
    kind: "commit_workspace",
    expectedEventSequence: prepared.state.eventSequence,
    now: 12,
    materializationTicketId: "ticket-commit",
    leaseFence,
    baseRevision: 0,
    workspaceCommitId: "workspace-commit-operation",
    postExecutionRootDigest: digest("1"),
    referencedObjectDigests: [digest("1")],
    protectionProofs: [
      {
        permitId: "permit-operation",
        tenantId: "tenant-1",
        objectDigest: digest("1"),
        guardGeneration: 1,
        status: "protected",
      } satisfies WorkspaceProtectionProof,
    ],
    authority: settlementAuthority,
  });
  return { committed, settlementAuthority };
}

describe("workspace effect operation identity", () => {
  it("rotates state and command schemas and fails closed on v2 shapes", async () => {
    expect(WORKSPACE_STATE_SCHEMA_VERSION).toBe(3);
    expect(WORKSPACE_COMMAND_SCHEMA_VERSION).toBe(3);

    const initial = createWorkspaceState({
      workspaceId: "workspace-operation",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    expect(initial.schemaVersion).toBe(3);

    const legacyAuthority = structuredClone(authority("legacy-command")) as Record<
      string,
      unknown
    >;
    Reflect.deleteProperty(legacyAuthority, "effectOperation");
    const untouchedInitial = structuredClone(initial);
    await expect(
      applyWorkspaceCommand(initial, {
        kind: "acquire_write_lease",
        expectedEventSequence: 0,
        now: 1,
        authority: legacyAuthority as unknown as WorkspaceAuthoritySnapshot,
        requestedLeaseId: "lease-legacy-command",
        sandboxId: "sandbox-legacy-command",
        backend: "nsjail",
        projectionGeneration: 1,
        requestedLeaseTtlMs: 100,
        requestedMaximumHoldMs: 500,
        acquireDeadline: 1_000,
        waitPolicy: "queue",
      }),
    ).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
    expect(initial).toEqual(untouchedInitial);
    expect(Object.hasOwn(legacyAuthority, "effectOperation")).toBe(false);

    const acquired = await acquiredLease(initial, "legacy-state", 2);
    const legacyState = structuredClone(acquired.result.state) as unknown as {
      schemaVersion: number;
      activeWriteLease: {
        admissionAuthority: Record<string, unknown>;
      } | null;
      leaseHistory: Record<string, unknown>[];
    };
    legacyState.schemaVersion = 2;
    if (legacyState.activeWriteLease !== null) {
      Reflect.deleteProperty(
        legacyState.activeWriteLease.admissionAuthority,
        "effectOperation",
      );
    }
    for (const history of legacyState.leaseHistory) {
      Reflect.deleteProperty(history, "effectOperation");
    }
    const untouchedLegacyState = structuredClone(legacyState);
    await expect(
      applyWorkspaceCommand(
        legacyState as unknown as WorkspaceAggregateState,
        {
          kind: "reconcile_write_queue",
          expectedEventSequence: acquired.result.state.eventSequence,
          now: 3,
        },
      ),
    ).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
    expect(legacyState).toEqual(untouchedLegacyState);
    expect(
      Object.hasOwn(
        legacyState.activeWriteLease?.admissionAuthority ?? {},
        "effectOperation",
      ),
    ).toBe(false);
  });

  it("binds acquisition, active history, retries, and the command digest to operation", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-operation",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    const acquired = await acquiredLease(initial, "active", 10);
    expect(acquired.lease.admissionAuthority).toMatchObject({
      effectOperation: "workspace.commit",
    });
    expect(acquired.result.state.leaseHistory).toContainEqual(
      expect.objectContaining({
        invocationId: "active",
        effectOperation: "workspace.commit",
        status: "active",
      }),
    );

    const expectedV3Digest = await digestStructuredValue(
      "circulusd.state-app.workspace-command",
      3,
      acquired.command,
    );
    const legacyV2Digest = await digestStructuredValue(
      "circulusd.state-app.workspace-command",
      2,
      acquired.command,
    );
    expect(acquired.result.commandDigest).toBe(expectedV3Digest);
    expect(acquired.result.commandDigest).not.toBe(legacyV2Digest);

    await expect(
      applyWorkspaceCommand(acquired.result.state, acquired.command),
    ).resolves.toMatchObject({ outcome: { kind: "write_lease_acquired" } });

    const relabeled = {
      ...acquired.command,
      authority: {
        ...acquired.command.authority,
        effectOperation: "workspace.delete",
      },
    };
    const untouched = structuredClone(acquired.result.state);
    await expect(
      applyWorkspaceCommand(acquired.result.state, relabeled),
    ).rejects.toMatchObject({ code: "STALE_GENERATION" });
    expect(acquired.result.state).toEqual(untouched);

    const corrupted = structuredClone(acquired.result.state);
    const activeHistory = corrupted.leaseHistory.find(
      (record) => record.invocationId === "active",
    ) as unknown as { effectOperation: string };
    activeHistory.effectOperation = "workspace.delete";
    expect(() => assertWorkspaceInvariants(corrupted)).toThrowError(
      expect.objectContaining({ code: "FAILED_PRECONDITION" }),
    );
  });

  it("fails closed on a v2 committed ledger without synthesizing operation", async () => {
    const { committed } = await committedWorkspace();
    const legacy = structuredClone(committed.state) as unknown as {
      schemaVersion: number;
      invocationLedger: Array<{
        commitAuthority: Record<string, unknown>;
      }>;
      leaseHistory: Record<string, unknown>[];
    };
    legacy.schemaVersion = 2;
    Reflect.deleteProperty(
      legacy.invocationLedger[0]?.commitAuthority ?? {},
      "effectOperation",
    );
    for (const history of legacy.leaseHistory) {
      Reflect.deleteProperty(history, "effectOperation");
    }
    const untouched = structuredClone(legacy);

    await expect(
      applyWorkspaceCommand(legacy as unknown as WorkspaceAggregateState, {
        kind: "reconcile_write_queue",
        expectedEventSequence: committed.state.eventSequence,
        now: 13,
      }),
    ).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
    expect(legacy).toEqual(untouched);
    expect(
      Object.hasOwn(
        legacy.invocationLedger[0]?.commitAuthority ?? {},
        "effectOperation",
      ),
    ).toBe(false);
  });

  it("binds queued, conflict, and released durable history to operation", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-operation",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    const owner = await acquiredLease(initial, "owner", 10);
    const waiter = await acquire(owner.result.state, "waiter", 11, {
      effectOperation: "workspace.write",
    });
    expect(waiter.result.outcome.kind).toBe("write_lease_queued");
    expect(waiter.result.state.leaseHistory).toContainEqual(
      expect.objectContaining({
        invocationId: "waiter",
        effectOperation: "workspace.write",
        status: "queued",
      }),
    );

    const relabeledWaiter = {
      ...waiter.command,
      authority: {
        ...waiter.command.authority,
        effectOperation: "workspace.delete",
      },
    };
    await expect(
      applyWorkspaceCommand(waiter.result.state, relabeledWaiter),
    ).rejects.toMatchObject({ code: "STALE_GENERATION" });

    const corruptedQueue = structuredClone(waiter.result.state);
    const queuedHistory = corruptedQueue.leaseHistory.find(
      (record) => record.invocationId === "waiter",
    ) as unknown as { effectOperation: string };
    queuedHistory.effectOperation = "workspace.delete";
    expect(() => assertWorkspaceInvariants(corruptedQueue)).toThrowError(
      expect.objectContaining({ code: "FAILED_PRECONDITION" }),
    );

    const conflictOne = await acquire(
      owner.result.state,
      "conflict",
      12,
      { effectOperation: "workspace.write" },
      "fail",
    );
    expect(conflictOne.result.outcome.kind).toBe("write_lease_conflict");
    await expect(
      acquire(
        conflictOne.result.state,
        "conflict",
        13,
        {
          dispatchAttempt: 2,
          effectOperation: "workspace.delete",
        },
        "fail",
      ),
    ).rejects.toMatchObject({ code: "STALE_GENERATION" });
    const conflictTwo = await acquire(
      conflictOne.result.state,
      "conflict",
      13,
      {
        dispatchAttempt: 2,
        effectOperation: "workspace.write",
      },
      "fail",
    );
    const corruptedConflict = structuredClone(conflictTwo.result.state);
    const latestConflict = corruptedConflict.leaseConflicts.at(-1);
    if (latestConflict === undefined) {
      throw new Error("expected a durable conflict receipt");
    }
    (latestConflict.authority as unknown as { effectOperation: string }).effectOperation =
      "workspace.delete";
    expect(() => assertWorkspaceInvariants(corruptedConflict)).toThrowError(
      expect.objectContaining({ code: "FAILED_PRECONDITION" }),
    );

    const released = await applyWorkspaceCommand(owner.result.state, {
      kind: "release_write_lease",
      expectedEventSequence: owner.result.state.eventSequence,
      now: 14,
      leaseFence: fence(owner.lease),
      authority: authority("owner"),
    });
    expect(released.state.leaseHistory).toContainEqual(
      expect.objectContaining({
        invocationId: "owner",
        effectOperation: "workspace.commit",
        status: "released",
      }),
    );
    const corruptedReleased = structuredClone(released.state);
    const releasedHistory = corruptedReleased.leaseHistory.find(
      (record) => record.invocationId === "owner",
    ) as unknown as Record<string, unknown>;
    Reflect.deleteProperty(releasedHistory, "effectOperation");
    expect(() => assertWorkspaceInvariants(corruptedReleased)).toThrowError(
      expect.objectContaining({ code: "INVALID_ARGUMENT" }),
    );
    await expect(
      acquire(released.state, "owner", 15, {
        dispatchAttempt: 2,
        effectOperation: "workspace.delete",
      }),
    ).rejects.toMatchObject({ code: "STALE_GENERATION" });
  });

  it("rejects committed history corruption and isolates exact from relabeled lookup", async () => {
    const { committed, settlementAuthority } = await committedWorkspace();
    expect(committed.state.leaseHistory).toContainEqual(
      expect.objectContaining({
        invocationId: "commit",
        effectOperation: "workspace.commit",
        status: "committed",
      }),
    );
    expect(committed.state.invocationLedger[0]?.commitAuthority).toMatchObject({
      effectOperation: "workspace.commit",
    });

    const corrupted = structuredClone(committed.state);
    const committedHistory = corrupted.leaseHistory.find(
      (record) => record.invocationId === "commit",
    ) as unknown as { effectOperation: string };
    committedHistory.effectOperation = "workspace.delete";
    expect(() => assertWorkspaceInvariants(corrupted)).toThrowError(
      expect.objectContaining({ code: "FAILED_PRECONDITION" }),
    );

    const calls = Array.from({ length: 32 }, (_, index) =>
      Promise.resolve().then(() =>
        lookupWorkspaceInvocation(
          committed.state,
          "commit",
          digest("a"),
          index % 2 === 0
            ? settlementAuthority
            : { ...settlementAuthority, effectOperation: "workspace.delete" },
          13,
        ),
      ),
    );
    const results = await Promise.allSettled(calls);
    for (const [index, result] of results.entries()) {
      if (index % 2 === 0) {
        expect(result).toMatchObject({
          status: "fulfilled",
          value: { status: "committed", invocationId: "commit" },
        });
      } else {
        expect(result).toMatchObject({
          status: "rejected",
          reason: { code: "STALE_GENERATION" },
        });
      }
    }
    expect(() => assertWorkspaceInvariants(committed.state)).not.toThrow();
  });
});
