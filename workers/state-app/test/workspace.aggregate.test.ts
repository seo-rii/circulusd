import { describe, expect, it } from "vitest";

import type { Digest } from "@circulusd/protocol-types";

import {
  applyWorkspaceCommand,
  createWorkspaceState,
  lookupWorkspaceInvocation,
  type WorkspaceAuthoritySnapshot,
  type WorkspaceLeaseFence,
  type WorkspaceProtectionProof,
} from "../src/workspace/index.ts";

const digest = (character: string): Digest =>
  `sha256:${character.repeat(64)}` as Digest;

const ROOT_ZERO = digest("0");
const ROOT_ONE = digest("1");
const REQUEST_WRITE = digest("a");
const REQUEST_READ = digest("b");

function authority(
  invocationId: string,
  requestDigest: Digest,
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
    turnLeaseExpiresAt: 20_000,
    effectStatus: "dispatched",
    effectId: `effect-${invocationId}`,
    invocationId,
    requestDigest,
    replayPolicy: "idempotency-key",
    dispatchAttempt: 1,
    turnLeaseGeneration: 3,
    placementGeneration: 5,
    sandboxGeneration: 7,
    sandboxId: `sandbox-${invocationId}`,
    backend: "nsjail",
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

function fenceFromLease(lease: {
  leaseId: string;
  invocationId: string;
  requestDigest: Digest;
  effectId: string;
  sessionId: string;
  sandboxId: string;
  leaseGeneration: number;
  dispatchAttempt: number;
  turnLeaseGeneration: number;
  placementGeneration: number;
  sandboxGeneration: number;
  projectionGeneration: number;
  authorizationGeneration: number;
}): WorkspaceLeaseFence {
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

describe("workspace transactional aggregate", () => {
  it("pins read-only materialization and commits revision, ledger, permits, and lease consumption atomically", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-1",
      tenantId: "tenant-1",
      initialRootDigest: ROOT_ZERO,
    });
    const untouched = structuredClone(initial);
    const writeAuthority = authority("write-1", REQUEST_WRITE, { expiresAt: 150 });

    const acquired = await applyWorkspaceCommand(initial, {
      kind: "acquire_write_lease",
      expectedEventSequence: 0,
      now: 100,
      authority: writeAuthority,
      requestedLeaseId: "lease-write-1",
      sandboxId: "sandbox-write-1",
      backend: "nsjail",
      projectionGeneration: 13,
      requestedLeaseTtlMs: 200,
      requestedMaximumHoldMs: 500,
      acquireDeadline: 1_000,
      waitPolicy: "queue",
    });
    expect(initial).toEqual(untouched);
    expect(acquired.outcome.kind).toBe("write_lease_acquired");
    if (acquired.outcome.kind !== "write_lease_acquired") {
      throw new Error("expected a lease");
    }
    const lease = acquired.outcome.lease;
    const fence = fenceFromLease(lease);
    const settlementAuthority = { ...writeAuthority, purpose: "settlement" } as const;

    await expect(
      applyWorkspaceCommand(acquired.state, {
        kind: "prepare_materialization",
        expectedEventSequence: 1,
        now: 160,
        ticketId: "ticket-expired-authority",
        accessMode: "read_write",
        requestedRevision: 0,
        authority: writeAuthority,
        sandboxId: "sandbox-write-1",
        backend: "nsjail",
        projectionGeneration: 13,
        leaseFence: fence,
        ticketTtlMs: 100,
      }),
    ).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });

    const readAuthority = authority("read-1", REQUEST_READ, {
      effectivePermissions: ["workspace.read"],
      sandboxGeneration: 17,
      sandboxId: "sandbox-read-1",
      backend: "docker",
    });
    const readPrepared = await applyWorkspaceCommand(acquired.state, {
      kind: "prepare_materialization",
      expectedEventSequence: 1,
      now: 110,
      ticketId: "ticket-read-1",
      accessMode: "read_only",
      requestedRevision: 0,
      authority: readAuthority,
      sandboxId: "sandbox-read-1",
      backend: "docker",
      projectionGeneration: 19,
      leaseFence: null,
      ticketTtlMs: 1_000,
    });
    expect(readPrepared.outcome.kind).toBe("materialization_prepared");
    if (readPrepared.outcome.kind !== "materialization_prepared") {
      throw new Error("expected a materialization ticket");
    }
    expect(readPrepared.outcome.ticket).toMatchObject({
      accessMode: "read_only",
      revision: 0,
      rootDigest: ROOT_ZERO,
      leaseId: null,
      leaseGeneration: null,
    });
    expect(readPrepared.state.activeWriteLease).toEqual(lease);
    expect(readPrepared.state.writeQueue).toHaveLength(0);

    const writePrepared = await applyWorkspaceCommand(readPrepared.state, {
      kind: "prepare_materialization",
      expectedEventSequence: 2,
      now: 120,
      ticketId: "ticket-write-1",
      accessMode: "read_write",
      requestedRevision: 0,
      authority: writeAuthority,
      sandboxId: "sandbox-write-1",
      backend: "nsjail",
      projectionGeneration: 13,
      leaseFence: fence,
      ticketTtlMs: 100,
    });

    await expect(
      applyWorkspaceCommand(writePrepared.state, {
        kind: "commit_workspace",
        expectedEventSequence: 3,
        now: 130,
        materializationTicketId: "ticket-write-1",
        leaseFence: fence,
        baseRevision: 1,
        workspaceCommitId: "commit-write-1",
        postExecutionRootDigest: ROOT_ONE,
        referencedObjectDigests: [ROOT_ONE, digest("f")],
        protectionProofs: [
          protectionProof("protect-1", ROOT_ONE),
          protectionProof("protect-2", digest("f")),
        ],
        authority: settlementAuthority,
      }),
    ).rejects.toMatchObject({ code: "CONFLICT" });

    const beforeCommit = structuredClone(writePrepared.state);
    const committed = await applyWorkspaceCommand(writePrepared.state, {
      kind: "commit_workspace",
      expectedEventSequence: 3,
      now: 130,
      materializationTicketId: "ticket-write-1",
      leaseFence: fence,
      baseRevision: 0,
      workspaceCommitId: "commit-write-1",
      postExecutionRootDigest: ROOT_ONE,
      referencedObjectDigests: [ROOT_ONE, digest("f")],
      protectionProofs: [
        protectionProof("protect-1", ROOT_ONE),
        protectionProof("protect-2", digest("f")),
      ],
      authority: settlementAuthority,
    });
    expect(writePrepared.state).toEqual(beforeCommit);
    expect(committed.outcome).toMatchObject({
      kind: "workspace_committed",
      result: {
        workspaceCommitId: "commit-write-1",
        revision: 1,
        rootDigest: ROOT_ONE,
      },
    });
    expect(committed.state).toMatchObject({
      revision: 1,
      rootDigest: ROOT_ONE,
      activeWriteLease: null,
    });
    expect(committed.state.revisions).toHaveLength(2);
    expect(committed.state.revisions[1]).toMatchObject({
      revision: 1,
      parentRevision: 0,
      rootDigest: ROOT_ONE,
      invocationId: "write-1",
      referencedObjectDigests: [ROOT_ONE, digest("f")],
      pendingProtectionPermitIds: ["protect-1", "protect-2"],
    });
    expect(committed.state.invocationLedger).toHaveLength(1);
    expect(committed.state.materializationTickets).toEqual([
      expect.objectContaining({
        ticketId: "ticket-read-1",
        revision: 0,
        rootDigest: ROOT_ZERO,
      }),
    ]);

    expect(
      lookupWorkspaceInvocation(
        committed.state,
        "write-1",
        REQUEST_WRITE,
        settlementAuthority,
        140,
      ),
    ).toMatchObject({
      status: "committed",
      result: { workspaceCommitId: "commit-write-1", revision: 1, rootDigest: ROOT_ONE },
    });

    const replayed = await applyWorkspaceCommand(committed.state, {
      kind: "commit_workspace",
      expectedEventSequence: 0,
      now: 140,
      materializationTicketId: "ticket-write-1",
      leaseFence: fence,
      baseRevision: 0,
      workspaceCommitId: "commit-write-1",
      postExecutionRootDigest: ROOT_ONE,
      referencedObjectDigests: [ROOT_ONE, digest("f")],
      protectionProofs: [
        protectionProof("protect-1", ROOT_ONE),
        protectionProof("protect-2", digest("f")),
      ],
      authority: settlementAuthority,
    });
    expect(replayed.replayed).toBe(true);
    expect(replayed.state).toBe(committed.state);
    expect(replayed.outcome).toEqual(committed.outcome);

    await expect(
      applyWorkspaceCommand(committed.state, {
        kind: "commit_workspace",
        expectedEventSequence: committed.state.eventSequence,
        now: 140,
        materializationTicketId: "ticket-write-1",
        leaseFence: { ...fence, requestDigest: digest("c") },
        baseRevision: 0,
        workspaceCommitId: "commit-corrupt",
        postExecutionRootDigest: digest("3"),
        referencedObjectDigests: [digest("3")],
        protectionProofs: [protectionProof("protect-corrupt", digest("3"))],
        authority: settlementAuthority,
      }),
    ).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
  });
});
