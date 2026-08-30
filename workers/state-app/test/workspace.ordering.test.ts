import { describe, expect, it } from "vitest";

import type { Digest } from "@circulusd/protocol-types";

import {
  applyWorkspaceCommand,
  createWorkspaceState,
  type AcquireWriteLeaseCommand,
  type WorkspaceAuthoritySnapshot,
  type WorkspaceLeaseFence,
  type WorkspaceWriteLease,
} from "../src/workspace/index.ts";

const digest = (character: string): Digest =>
  `sha256:${character.repeat(64)}` as Digest;

function authority(
  invocationId: string,
  requestDigest = digest("a"),
  overrides: Partial<WorkspaceAuthoritySnapshot> = {},
): WorkspaceAuthoritySnapshot {
  return {
    purpose: "admission",
    serviceBinding: "workspace",
    tenantId: "tenant-1",
    userId: "user-1",
    sessionId: `session-${invocationId}`,
    workspaceId: "workspace-1",
    turnId: `turn-${invocationId}`,
    runtimeRevision: "runtime-1",
    policySnapshotDigest: digest("d"),
    emergencyOverlayDigest: digest("e"),
    effectivePermissions: ["workspace.read", "workspace.write"],
    sessionStatus: "active",
    turnStatus: "active",
    turnLeaseActive: true,
    turnLeaseExpiresAt: 200_000,
    effectStatus: "dispatched",
    effectService: "workspace",
    effectOperation: "workspace.commit",
    effectId: `effect-${invocationId}`,
    invocationId,
    requestDigest,
    replayPolicy: "idempotency-key",
    dispatchAttempt: 1,
    turnLeaseGeneration: 1,
    placementGeneration: 1,
    sandboxGeneration: 1,
    sandboxId: `sandbox-${invocationId}`,
    backend: "nsjail",
    authorizationGeneration: 1,
    issuedAt: 0,
    expiresAt: 100_000,
    ...overrides,
  };
}

function acquire(
  invocationId: string,
  expectedEventSequence: number,
  now: number,
  acquireDeadline = 10_000,
  workspaceId = "workspace-1",
): AcquireWriteLeaseCommand {
  return {
    kind: "acquire_write_lease",
    expectedEventSequence,
    now,
    authority: authority(invocationId, digest("a"), { workspaceId }),
    requestedLeaseId: `lease-${invocationId}`,
    sandboxId: `sandbox-${invocationId}`,
    backend: "nsjail",
    projectionGeneration: 1,
    requestedLeaseTtlMs: 1_000,
    requestedMaximumHoldMs: 5_000,
    acquireDeadline,
    waitPolicy: "queue",
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

async function acquireLease(
  state: ReturnType<typeof createWorkspaceState>,
  invocationId: string,
  expectedEventSequence: number,
  now: number,
) {
  const result = await applyWorkspaceCommand(
    state,
    acquire(invocationId, expectedEventSequence, now, 10_000, state.workspaceId),
  );
  if (result.outcome.kind !== "write_lease_acquired") {
    throw new Error("expected acquired lease");
  }
  return result;
}

describe("workspace write lease ordering", () => {
  it("rejects an idempotency key reused with different lease admission bounds", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-idempotency",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    const owner = await applyWorkspaceCommand(
      initial,
      acquire("owner", 0, 10, 10_000, initial.workspaceId),
    );

    await expect(
      applyWorkspaceCommand(owner.state, {
        ...acquire("owner", 0, 11, 10_000, initial.workspaceId),
        requestedLeaseId: "different-lease-id",
      }),
    ).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });

    const queued = await applyWorkspaceCommand(
      owner.state,
      acquire("waiter", 1, 12, 10_000, initial.workspaceId),
    );
    await expect(
      applyWorkspaceCommand(queued.state, {
        ...acquire("waiter", 0, 13, 10_000, initial.workspaceId),
        requestedLeaseTtlMs: 2_000,
      }),
    ).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
  });

  it("models concurrent transactions with optimistic sequencing and preserves idempotent FIFO position", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-1",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    const commandA = acquire("a", 0, 10);
    const commandB = acquire("b", 0, 10);
    const held = await applyWorkspaceCommand(initial, commandA);
    const independentlyHeld = await applyWorkspaceCommand(structuredClone(initial), commandA);
    expect(independentlyHeld.commandDigest).toBe(held.commandDigest);
    expect(independentlyHeld.state).toEqual(held.state);

    await expect(applyWorkspaceCommand(held.state, commandB)).rejects.toMatchObject({
      code: "CONFLICT",
    });

    const queuedB = await applyWorkspaceCommand(held.state, {
      ...commandB,
      expectedEventSequence: 1,
    });
    expect(queuedB.outcome).toMatchObject({
      kind: "write_lease_queued",
      enqueueSequence: 1,
      queuePosition: 1,
    });
    const retriedB = await applyWorkspaceCommand(queuedB.state, {
      ...commandB,
      expectedEventSequence: 0,
      now: 11,
    });
    expect(retriedB.replayed).toBe(true);
    expect(retriedB.state).toBe(queuedB.state);
    expect(retriedB.outcome).toEqual(queuedB.outcome);

    const queuedC = await applyWorkspaceCommand(
      queuedB.state,
      acquire("c", 2, 12),
    );
    expect(queuedC.outcome).toMatchObject({
      kind: "write_lease_queued",
      enqueueSequence: 2,
      queuePosition: 2,
    });

    await expect(
      applyWorkspaceCommand(queuedC.state, {
        ...acquire("b", 3, 13),
        authority: authority("b", digest("b")),
      }),
    ).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });

    const cancelled = await applyWorkspaceCommand(queuedC.state, {
      kind: "cancel_write_lease_request",
      expectedEventSequence: 3,
      now: 14,
      invocationId: "b",
      requestDigest: digest("a"),
      authority: authority("b"),
    });
    expect(cancelled.state.writeQueue[0]).toMatchObject({
      authority: { invocationId: "b" },
      canceled: true,
    });

    if (held.outcome.kind !== "write_lease_acquired") {
      throw new Error("expected the first lease");
    }
    const released = await applyWorkspaceCommand(cancelled.state, {
      kind: "release_write_lease",
      expectedEventSequence: 4,
      now: 15,
      leaseFence: fence(held.outcome.lease),
      authority: authority("a"),
    });
    expect(released.outcome).toMatchObject({
      kind: "write_lease_released",
      promotedInvocationId: null,
    });
    expect(released.state.activeWriteLease).toBeNull();
    expect(released.state.writeQueue).toEqual([
      expect.objectContaining({
        authority: expect.objectContaining({ invocationId: "c" }),
        enqueueSequence: 2,
      }),
    ]);

    const grantedC = await applyWorkspaceCommand(released.state, {
      ...acquire("c", released.state.eventSequence, 16),
      authority: authority("c", digest("a"), { issuedAt: 15 }),
    });
    expect(grantedC.outcome).toMatchObject({
      kind: "write_lease_acquired",
      lease: {
      invocationId: "c",
      enqueueSequence: 2,
      leaseGeneration: 2,
      },
    });
    expect(grantedC.state.writeQueue).toHaveLength(0);
  });

  it("prepares a fixed read-only snapshot without joining or disturbing the writer queue", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-read-only",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    const owner = await acquireLease(initial, "owner", 0, 10);
    const queued = await applyWorkspaceCommand(
      owner.state,
      acquire("writer-2", 1, 11, 10_000, initial.workspaceId),
    );
    const queueBeforeRead = structuredClone(queued.state.writeQueue);
    const activeBeforeRead = structuredClone(queued.state.activeWriteLease);
    const nextEnqueueBeforeRead = queued.state.nextLeaseEnqueueSequence;

    const prepared = await applyWorkspaceCommand(queued.state, {
      kind: "prepare_materialization",
      expectedEventSequence: 2,
      now: 12,
      ticketId: "ticket-read-only",
      accessMode: "read_only",
      requestedRevision: 0,
      authority: authority("reader", digest("b"), {
        workspaceId: initial.workspaceId,
        sandboxId: "sandbox-reader",
        backend: "docker",
        effectivePermissions: ["workspace.read"],
      }),
      sandboxId: "sandbox-reader",
      backend: "docker",
      projectionGeneration: 9,
      leaseFence: null,
      ticketTtlMs: 500,
    });
    expect(prepared.outcome).toMatchObject({
      kind: "materialization_prepared",
      ticket: { accessMode: "read_only", revision: 0, rootDigest: digest("0") },
    });
    expect(prepared.state.activeWriteLease).toEqual(activeBeforeRead);
    expect(prepared.state.writeQueue).toEqual(queueBeforeRead);
    expect(prepared.state.nextLeaseEnqueueSequence).toBe(nextEnqueueBeforeRead);
  });

  it("skips timed-out FIFO heads and grants the earliest eligible fresh retry across repeated schedules", async () => {
    for (let round = 0; round < 32; round += 1) {
      let current = createWorkspaceState({
        workspaceId: `workspace-${round}`,
        tenantId: "tenant-1",
        initialRootDigest: digest("0"),
      });
      const owner = await acquireLease(current, "owner", 0, 1);
      current = owner.state;

      const waiterCount = 3 + (round % 7);
      let firstEligible: string | null = null;
      const releaseAt = 100;
      for (let index = 0; index < waiterCount; index += 1) {
        const invocationId = `waiter-${index}`;
        const timedOut = index < (round % waiterCount);
        const deadline = timedOut ? releaseAt : releaseAt + 1_000 + index;
        const result = await applyWorkspaceCommand(
          current,
          acquire(
            invocationId,
            current.eventSequence,
            2 + index,
            deadline,
            current.workspaceId,
          ),
        );
        current = result.state;
        if (!timedOut && firstEligible === null) {
          firstEligible = invocationId;
        }
      }

      if (owner.outcome.kind !== "write_lease_acquired") {
        throw new Error("expected acquired lease");
      }
      const released = await applyWorkspaceCommand(current, {
        kind: "release_write_lease",
        expectedEventSequence: current.eventSequence,
        now: releaseAt,
        leaseFence: fence(owner.outcome.lease),
        authority: authority("owner", digest("a"), { workspaceId: current.workspaceId }),
      });
      expect(released.outcome).toMatchObject({
        kind: "write_lease_released",
        promotedInvocationId: null,
      });
      expect(released.state.activeWriteLease).toBeNull();
      expect(released.state.writeQueue[0]?.authority.invocationId ?? null).toBe(
        firstEligible,
      );
      if (firstEligible !== null) {
        const expectedIndex = Number(firstEligible.split("-")[1]);
        const granted = await applyWorkspaceCommand(released.state, {
          ...acquire(
            firstEligible,
            released.state.eventSequence,
            releaseAt + 1,
            releaseAt + 1_000 + expectedIndex,
            current.workspaceId,
          ),
          authority: authority(firstEligible, digest("a"), {
            workspaceId: current.workspaceId,
            issuedAt: releaseAt,
          }),
        });
        expect(granted.outcome).toMatchObject({
          kind: "write_lease_acquired",
          lease: {
            invocationId: firstEligible,
            enqueueSequence: expectedIndex + 1,
          },
        });
      }
    }
  });

  it("preserves an already admitted FIFO waiter after its authority TTL expires", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-authority-deadline",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    const owner = await acquireLease(initial, "owner", 0, 1);
    const expired = await applyWorkspaceCommand(owner.state, {
      ...acquire("expired", 1, 2, 1_000, initial.workspaceId),
      authority: authority("expired", digest("a"), {
        workspaceId: initial.workspaceId,
        expiresAt: 50,
      }),
    });
    const live = await applyWorkspaceCommand(
      expired.state,
      acquire("live", 2, 3, 1_000, initial.workspaceId),
    );
    if (owner.outcome.kind !== "write_lease_acquired") {
      throw new Error("expected acquired lease");
    }

    const released = await applyWorkspaceCommand(live.state, {
      kind: "release_write_lease",
      expectedEventSequence: 3,
      now: 100,
      leaseFence: fence(owner.outcome.lease),
      authority: authority("owner", digest("a"), { workspaceId: initial.workspaceId }),
    });
    expect(released.outcome).toMatchObject({
      kind: "write_lease_released",
      promotedInvocationId: null,
    });
    expect(released.state.activeWriteLease).toBeNull();
    expect(released.state.writeQueue[0]).toMatchObject({
      authority: { invocationId: "expired" },
      enqueueSequence: 1,
    });
    expect(
      released.state.leaseHistory.find((record) => record.invocationId === "expired"),
    ).toMatchObject({ status: "queued", latestEnqueueSequence: 1 });

    const granted = await applyWorkspaceCommand(released.state, {
      ...acquire(
        "expired",
        released.state.eventSequence,
        101,
        1_000,
        initial.workspaceId,
      ),
      authority: authority("expired", digest("a"), {
        workspaceId: initial.workspaceId,
        issuedAt: 100,
      }),
    });
    expect(granted.outcome).toMatchObject({
      kind: "write_lease_acquired",
      lease: { invocationId: "expired", enqueueSequence: 1 },
    });
    expect(granted.state.writeQueue[0]).toMatchObject({
      authority: { invocationId: "live" },
      enqueueSequence: 2,
    });
  });
});
