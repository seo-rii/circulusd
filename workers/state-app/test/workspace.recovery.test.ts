import { describe, expect, it } from "vitest";

import type { Digest } from "@circulusd/protocol-types";

import {
  applyWorkspaceCommand,
  createWorkspaceState,
  lookupWorkspaceInvocation,
  type WorkspaceAuthoritySnapshot,
  type WorkspaceLeaseFence,
  type WorkspaceProtectionProof,
  type WorkspaceWriteLease,
} from "../src/workspace/index.ts";

const digest = (character: string): Digest =>
  `sha256:${character.repeat(64)}` as Digest;

const REQUEST = digest("a");

function authority(
  overrides: Partial<WorkspaceAuthoritySnapshot> = {},
): WorkspaceAuthoritySnapshot {
  return {
    purpose: "admission",
    serviceBinding: "workspace",
    tenantId: "tenant-1",
    userId: "user-1",
    sessionId: "session-1",
    workspaceId: "workspace-1",
    turnId: "turn-1",
    runtimeRevision: "runtime-1",
    policySnapshotDigest: digest("d"),
    emergencyOverlayDigest: digest("e"),
    effectivePermissions: ["workspace.read", "workspace.write"],
    sessionStatus: "active",
    turnStatus: "active",
    turnLeaseActive: true,
    turnLeaseExpiresAt: 20_000,
    effectStatus: "dispatched",
    effectId: "effect-1",
    invocationId: "invocation-1",
    requestDigest: REQUEST,
    replayPolicy: "idempotency-key",
    dispatchAttempt: 2,
    turnLeaseGeneration: 3,
    placementGeneration: 5,
    sandboxGeneration: 7,
    sandboxId: "sandbox-1",
    backend: "firecracker",
    authorizationGeneration: 11,
    issuedAt: 0,
    expiresAt: 10_000,
    ...overrides,
  };
}

function protectionProof(
  permitId: string,
  objectDigest: Digest,
): WorkspaceProtectionProof {
  return {
    permitId,
    tenantId: "tenant-1",
    objectDigest,
    guardGeneration: 1,
    status: "protected",
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
  state: ReturnType<typeof createWorkspaceState>,
  projectionGeneration: number,
  requestedLeaseId: string,
  expectedEventSequence: number,
  now: number,
  authorityOverrides: Partial<WorkspaceAuthoritySnapshot> = {},
) {
  return applyWorkspaceCommand(state, {
    kind: "acquire_write_lease",
    expectedEventSequence,
    now,
    authority: authority({ workspaceId: state.workspaceId, ...authorityOverrides }),
    requestedLeaseId,
    sandboxId: "sandbox-1",
    backend: "firecracker",
    projectionGeneration,
    requestedLeaseTtlMs: 100,
    requestedMaximumHoldMs: 300,
    acquireDeadline: 10_000,
    waitPolicy: "queue",
  });
}

describe("workspace lease fencing and recovery", () => {
  it("renews by exact sequence, caps maximum hold, and requires a new lease and projection after expiry", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-1",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    const currentAuthority = authority({ workspaceId: initial.workspaceId });
    const acquired = await acquire(initial, 13, "lease-1", 0, 100);
    if (acquired.outcome.kind !== "write_lease_acquired") {
      throw new Error("expected acquired lease");
    }
    const oldLease = acquired.outcome.lease;
    const oldFence = fence(oldLease);
    expect(oldLease).toMatchObject({
      leaseGeneration: 1,
      issuedAt: 100,
      expiresAt: 200,
      maximumHoldDeadline: 400,
      renewalSequence: 0,
      projectionGeneration: 13,
    });

    const renewedOnce = await applyWorkspaceCommand(acquired.state, {
      kind: "renew_write_lease",
      expectedEventSequence: 1,
      now: 150,
      leaseFence: oldFence,
      nextRenewalSequence: 1,
      requestedLeaseTtlMs: 100,
      authority: currentAuthority,
    });
    expect(renewedOnce.outcome).toMatchObject({
      kind: "write_lease_renewed",
      expiresAt: 250,
      renewalSequence: 1,
    });

    const retriedRenewal = await applyWorkspaceCommand(renewedOnce.state, {
      kind: "renew_write_lease",
      expectedEventSequence: 0,
      now: 151,
      leaseFence: oldFence,
      nextRenewalSequence: 1,
      requestedLeaseTtlMs: 100,
      authority: currentAuthority,
    });
    expect(retriedRenewal.replayed).toBe(true);
    expect(retriedRenewal.state).toBe(renewedOnce.state);
    expect(retriedRenewal.outcome).toMatchObject({
      expiresAt: 250,
      renewalSequence: 1,
    });

    await expect(
      applyWorkspaceCommand(renewedOnce.state, {
        kind: "renew_write_lease",
        expectedEventSequence: 2,
        now: 152,
        leaseFence: oldFence,
        nextRenewalSequence: 1,
        requestedLeaseTtlMs: 101,
        authority: currentAuthority,
      }),
    ).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
    await expect(
      applyWorkspaceCommand(renewedOnce.state, {
        kind: "renew_write_lease",
        expectedEventSequence: 2,
        now: 152,
        leaseFence: oldFence,
        nextRenewalSequence: 3,
        requestedLeaseTtlMs: 100,
        authority: currentAuthority,
      }),
    ).rejects.toMatchObject({ code: "STALE_GENERATION" });

    const renewedToMaximum = await applyWorkspaceCommand(renewedOnce.state, {
      kind: "renew_write_lease",
      expectedEventSequence: 2,
      now: 200,
      leaseFence: oldFence,
      nextRenewalSequence: 2,
      requestedLeaseTtlMs: 1_000,
      authority: currentAuthority,
    });
    expect(renewedToMaximum.outcome).toMatchObject({ expiresAt: 400 });
    await expect(
      applyWorkspaceCommand(renewedToMaximum.state, {
        kind: "renew_write_lease",
        expectedEventSequence: 3,
        now: 400,
        leaseFence: oldFence,
        nextRenewalSequence: 3,
        requestedLeaseTtlMs: 1,
        authority: currentAuthority,
      }),
    ).rejects.toMatchObject({ code: "LEASE_EXPIRED" });

    await expect(
      acquire(renewedToMaximum.state, 13, "lease-2", 3, 401, { dispatchAttempt: 3 }),
    ).rejects.toMatchObject({ code: "STALE_GENERATION" });
    const reacquired = await acquire(renewedToMaximum.state, 14, "lease-2", 3, 401, {
      dispatchAttempt: 3,
    });
    expect(reacquired.outcome).toMatchObject({
      kind: "write_lease_acquired",
      lease: { leaseGeneration: 2, projectionGeneration: 14, baseRevision: 0 },
    });
    expect(reacquired.state.materializationTickets).toHaveLength(0);

    await expect(
      applyWorkspaceCommand(reacquired.state, {
        kind: "commit_workspace",
        expectedEventSequence: 4,
        now: 402,
        materializationTicketId: "stale-ticket",
        leaseFence: oldFence,
        baseRevision: 0,
        workspaceCommitId: "stale-commit",
        postExecutionRootDigest: digest("1"),
        referencedObjectDigests: [digest("1")],
        protectionProofs: [protectionProof("protect-stale", digest("1"))],
        authority: { ...currentAuthority, purpose: "settlement" },
      }),
    ).rejects.toMatchObject({ code: "STALE_GENERATION" });
  });

  it("recovers a committed result from a cloned invocation ledger after the lease was consumed", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-recovery",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    const currentAuthority = authority({ workspaceId: initial.workspaceId });
    const acquired = await acquire(initial, 1, "lease-recovery", 0, 10);
    if (acquired.outcome.kind !== "write_lease_acquired") {
      throw new Error("expected acquired lease");
    }
    const currentFence = fence(acquired.outcome.lease);
    const prepared = await applyWorkspaceCommand(acquired.state, {
      kind: "prepare_materialization",
      expectedEventSequence: 1,
      now: 11,
      ticketId: "ticket-recovery",
      accessMode: "read_write",
      requestedRevision: 0,
      authority: currentAuthority,
      sandboxId: "sandbox-1",
      backend: "firecracker",
      projectionGeneration: 1,
      leaseFence: currentFence,
      ticketTtlMs: 50,
    });
    const committed = await applyWorkspaceCommand(prepared.state, {
      kind: "commit_workspace",
      expectedEventSequence: 2,
      now: 12,
      materializationTicketId: "ticket-recovery",
      leaseFence: currentFence,
      baseRevision: 0,
      workspaceCommitId: "workspace-commit-recovery",
      postExecutionRootDigest: digest("f"),
      referencedObjectDigests: [digest("f")],
      protectionProofs: [protectionProof("protection-recovery", digest("f"))],
      authority: { ...currentAuthority, purpose: "settlement" },
    });

    const recoveredState = structuredClone(committed.state);
    expect(recoveredState.activeWriteLease).toBeNull();
    expect(
      lookupWorkspaceInvocation(
        recoveredState,
        "invocation-1",
        REQUEST,
        { ...currentAuthority, purpose: "settlement" },
        13,
      ),
    ).toMatchObject({
      status: "committed",
      result: {
        workspaceCommitId: "workspace-commit-recovery",
        revision: 1,
        rootDigest: digest("f"),
      },
    });

    const replay = await applyWorkspaceCommand(recoveredState, {
      kind: "commit_workspace",
      expectedEventSequence: 0,
      now: 99,
      materializationTicketId: "ticket-recovery",
      leaseFence: currentFence,
      baseRevision: 0,
      workspaceCommitId: "workspace-commit-recovery",
      postExecutionRootDigest: digest("f"),
      referencedObjectDigests: [digest("f")],
      protectionProofs: [protectionProof("protection-recovery", digest("f"))],
      authority: { ...currentAuthority, purpose: "settlement" },
    });
    expect(replay.replayed).toBe(true);
    expect(replay.outcome).toEqual(committed.outcome);
  });
});
