import { describe, expect, it } from "vitest";

import type { Digest } from "@circulusd/protocol-types";

import {
  applyWorkspaceCommand,
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
    turnLeaseExpiresAt: 10_000,
    effectStatus: "dispatched",
    effectService: "workspace",
    effectId: `effect-${invocationId}`,
    invocationId,
    requestDigest,
    replayPolicy: "idempotency-key",
    dispatchAttempt: 1,
    sandboxId: `sandbox-${invocationId}`,
    backend: "nsjail",
    turnLeaseGeneration: 3,
    placementGeneration: 5,
    sandboxGeneration: 7,
    authorizationGeneration: 11,
    issuedAt: 0,
    expiresAt: 5_000,
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

function proof(permitId: string, objectDigest: Digest): WorkspaceProtectionProof {
  return {
    permitId,
    tenantId: "tenant-1",
    objectDigest,
    guardGeneration: 1,
    status: "protected",
  };
}

async function acquire(
  state: WorkspaceAggregateState,
  currentAuthority: WorkspaceAuthoritySnapshot,
  options: {
    readonly now: number;
    readonly leaseId: string;
    readonly waitPolicy?: "queue" | "fail";
    readonly projectionGeneration?: number;
    readonly expectedEventSequence?: number;
  },
) {
  return applyWorkspaceCommand(state, {
    kind: "acquire_write_lease",
    expectedEventSequence: options.expectedEventSequence ?? state.eventSequence,
    now: options.now,
    authority: currentAuthority,
    requestedLeaseId: options.leaseId,
    sandboxId: currentAuthority.sandboxId,
    backend: currentAuthority.backend,
    projectionGeneration: options.projectionGeneration ?? 1,
    requestedLeaseTtlMs: 500,
    requestedMaximumHoldMs: 2_000,
    acquireDeadline: 4_000,
    waitPolicy: options.waitPolicy ?? "queue",
  });
}

async function preparedWrite(
  state: WorkspaceAggregateState,
  currentAuthority: WorkspaceAuthoritySnapshot,
  ticketTtlMs = 500,
) {
  const acquired = await acquire(state, currentAuthority, {
    now: 10,
    leaseId: `lease-${currentAuthority.invocationId}`,
  });
  if (acquired.outcome.kind !== "write_lease_acquired") {
    throw new Error("expected acquired lease");
  }
  const leaseFence = fence(acquired.outcome.lease);
  const prepared = await applyWorkspaceCommand(acquired.state, {
    kind: "prepare_materialization",
    expectedEventSequence: acquired.state.eventSequence,
    now: 11,
    ticketId: `ticket-${currentAuthority.invocationId}`,
    accessMode: "read_write",
    requestedRevision: 0,
    authority: currentAuthority,
    sandboxId: currentAuthority.sandboxId,
    backend: currentAuthority.backend,
    projectionGeneration: 1,
    leaseFence,
    ticketTtlMs,
  });
  return { acquired, prepared, leaseFence };
}

describe("workspace independent-review regressions", () => {
  it("rejects authority accessors without executing extension-controlled getters", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-1",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    let getterCalls = 0;
    const hostileAuthority = authority("hostile", digest("a"));
    Object.defineProperty(hostileAuthority, "invocationId", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return "hostile";
      },
    });

    await expect(
      acquire(initial, hostileAuthority, { now: 1, leaseId: "lease-hostile" }),
    ).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
    expect(getterCalls).toBe(0);
  });

  it("rejects a command-kind accessor before dispatching on it", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-1",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    let getterCalls = 0;
    const hostile = {
      kind: "acquire_write_lease",
      expectedEventSequence: 0,
      now: 1,
      authority: authority("hostile-kind", digest("a")),
      requestedLeaseId: "lease-hostile-kind",
      sandboxId: "sandbox-hostile-kind",
      backend: "nsjail",
      projectionGeneration: 1,
      requestedLeaseTtlMs: 100,
      requestedMaximumHoldMs: 500,
      acquireDeadline: 1_000,
      waitPolicy: "queue",
    };
    Object.defineProperty(hostile, "kind", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return "acquire_write_lease";
      },
    });

    await expect(applyWorkspaceCommand(initial, hostile as never)).rejects.toMatchObject({
      code: "INVALID_ARGUMENT",
    });
    expect(getterCalls).toBe(0);
  });

  it("allows only authorization rotation for a new settlement and broader rotation for terminal replay", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-1",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    const original = authority("rotated", digest("a"));
    const { prepared, leaseFence } = await preparedWrite(initial, original);
    const authorizationRotated: WorkspaceAuthoritySnapshot = {
      ...original,
      purpose: "settlement",
      emergencyOverlayDigest: digest("f"),
      effectivePermissions: ["workspace.read"],
      authorizationGeneration: original.authorizationGeneration + 1,
    };
    const root = digest("1");
    const committed = await applyWorkspaceCommand(prepared.state, {
      kind: "commit_workspace",
      expectedEventSequence: prepared.state.eventSequence,
      now: 20,
      materializationTicketId: "ticket-rotated",
      leaseFence,
      baseRevision: 0,
      workspaceCommitId: "commit-rotated",
      postExecutionRootDigest: root,
      referencedObjectDigests: [root],
      protectionProofs: [proof("proof-rotated", root)],
      authority: authorizationRotated,
    });

    const recoveryAuthority: WorkspaceAuthoritySnapshot = {
      ...authorizationRotated,
      turnLeaseGeneration: authorizationRotated.turnLeaseGeneration + 1,
      placementGeneration: authorizationRotated.placementGeneration + 1,
      authorizationGeneration: authorizationRotated.authorizationGeneration + 1,
      effectStatus: "externally_committed",
    };
    expect(
      lookupWorkspaceInvocation(
        committed.state,
        original.invocationId,
        original.requestDigest,
        recoveryAuthority,
        30,
      ),
    ).toMatchObject({ result: { workspaceCommitId: "commit-rotated" } });
    const replayed = await applyWorkspaceCommand(committed.state, {
      kind: "commit_workspace",
      expectedEventSequence: 0,
      now: 30,
      materializationTicketId: "ticket-rotated",
      leaseFence,
      baseRevision: 0,
      workspaceCommitId: "commit-rotated",
      postExecutionRootDigest: root,
      referencedObjectDigests: [root],
      protectionProofs: [proof("proof-rotated", root)],
      authority: recoveryAuthority,
    });
    expect(replayed.replayed).toBe(true);

    await expect(
      applyWorkspaceCommand(prepared.state, {
        kind: "commit_workspace",
        expectedEventSequence: prepared.state.eventSequence,
        now: 20,
        materializationTicketId: "ticket-rotated",
        leaseFence,
        baseRevision: 0,
        workspaceCommitId: "commit-wrong-placement",
        postExecutionRootDigest: digest("2"),
        referencedObjectDigests: [digest("2")],
        protectionProofs: [proof("proof-wrong-placement", digest("2"))],
        authority: {
          ...authorizationRotated,
          placementGeneration: authorizationRotated.placementGeneration + 1,
        },
      }),
    ).rejects.toMatchObject({ code: "STALE_GENERATION" });
  });

  it("keeps a queued head inert until the waiter retries with current authority", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-1",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    const ownerAuthority = authority("owner", digest("a"));
    const waiterV1 = authority("waiter", digest("b"));
    const owner = await acquire(initial, ownerAuthority, { now: 1, leaseId: "lease-owner" });
    if (owner.outcome.kind !== "write_lease_acquired") {
      throw new Error("expected owner lease");
    }
    const queued = await acquire(owner.state, waiterV1, { now: 2, leaseId: "lease-waiter" });
    expect(queued.outcome.kind).toBe("write_lease_queued");
    const released = await applyWorkspaceCommand(queued.state, {
      kind: "release_write_lease",
      expectedEventSequence: queued.state.eventSequence,
      now: 3,
      leaseFence: fence(owner.outcome.lease),
      authority: ownerAuthority,
    });
    expect(released.outcome).toMatchObject({
      kind: "write_lease_released",
      promotedInvocationId: null,
    });
    expect(released.state.activeWriteLease).toBeNull();
    expect(released.state.writeQueue[0]?.authority.invocationId).toBe("waiter");

    const waiterV2 = {
      ...waiterV1,
      emergencyOverlayDigest: digest("c"),
      authorizationGeneration: waiterV1.authorizationGeneration + 1,
    };
    const granted = await acquire(released.state, waiterV2, {
      now: 4,
      leaseId: "lease-waiter",
    });
    expect(granted.outcome).toMatchObject({
      kind: "write_lease_acquired",
      lease: { invocationId: "waiter", authorizationGeneration: 12, enqueueSequence: 1 },
    });
  });

  it("persists fail-policy conflicts and replays them after the owner releases", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-1",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    const ownerAuthority = authority("owner-conflict", digest("a"));
    const contenderAuthority = authority("contender", digest("b"));
    const owner = await acquire(initial, ownerAuthority, { now: 1, leaseId: "lease-owner" });
    if (owner.outcome.kind !== "write_lease_acquired") {
      throw new Error("expected owner lease");
    }
    const conflicted = await acquire(owner.state, contenderAuthority, {
      now: 2,
      leaseId: "lease-contender",
      waitPolicy: "fail",
    });
    expect(conflicted.outcome.kind).toBe("write_lease_conflict");
    expect(
      (conflicted.state as WorkspaceAggregateState & { leaseConflicts: readonly unknown[] })
        .leaseConflicts,
    ).toHaveLength(1);
    const released = await applyWorkspaceCommand(conflicted.state, {
      kind: "release_write_lease",
      expectedEventSequence: conflicted.state.eventSequence,
      now: 3,
      leaseFence: fence(owner.outcome.lease),
      authority: ownerAuthority,
    });
    const replayed = await acquire(released.state, contenderAuthority, {
      now: 4,
      leaseId: "lease-contender",
      waitPolicy: "fail",
      expectedEventSequence: 0,
    });
    expect(replayed.replayed).toBe(true);
    expect(replayed.state).toBe(released.state);
    expect(replayed.outcome).toEqual(conflicted.outcome);

    const retried = await acquire(
      released.state,
      { ...contenderAuthority, dispatchAttempt: 2 },
      {
        now: 5,
        leaseId: "lease-contender-retry",
        waitPolicy: "fail",
        projectionGeneration: 2,
      },
    );
    expect(retried.outcome.kind).toBe("write_lease_acquired");
  });

  it("requires one protection proof for every declared root closure object", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-1",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    const currentAuthority = authority("closure", digest("a"));
    const { prepared, leaseFence } = await preparedWrite(initial, currentAuthority);
    const child = digest("1");
    const root = digest("2");
    await expect(
      applyWorkspaceCommand(prepared.state, {
        kind: "commit_workspace",
        expectedEventSequence: prepared.state.eventSequence,
        now: 20,
        materializationTicketId: "ticket-closure",
        leaseFence,
        baseRevision: 0,
        workspaceCommitId: "commit-missing-child-proof",
        postExecutionRootDigest: root,
        referencedObjectDigests: [child, root],
        protectionProofs: [proof("proof-root", root)],
        authority: { ...currentAuthority, purpose: "settlement" },
      }),
    ).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });

    const committed = await applyWorkspaceCommand(prepared.state, {
      kind: "commit_workspace",
      expectedEventSequence: prepared.state.eventSequence,
      now: 20,
      materializationTicketId: "ticket-closure",
      leaseFence,
      baseRevision: 0,
      workspaceCommitId: "commit-complete-closure",
      postExecutionRootDigest: root,
      referencedObjectDigests: [child, root],
      protectionProofs: [proof("proof-child", child), proof("proof-root", root)],
      authority: { ...currentAuthority, purpose: "settlement" },
    });
    expect(committed.state.revisions[1]).toMatchObject({
      referencedObjectDigests: [child, root],
      pendingProtectionPermitIds: ["proof-child", "proof-root"],
    });
  });

  it("accepts protection permit IDs in canonical UTF-8 byte order", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-1",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    const currentAuthority = authority("unicode-proof", digest("a"));
    const { prepared, leaseFence } = await preparedWrite(initial, currentAuthority);
    const child = digest("1");
    const root = digest("2");
    const committed = await applyWorkspaceCommand(prepared.state, {
      kind: "commit_workspace",
      expectedEventSequence: prepared.state.eventSequence,
      now: 20,
      materializationTicketId: "ticket-unicode-proof",
      leaseFence,
      baseRevision: 0,
      workspaceCommitId: "commit-unicode-proof",
      postExecutionRootDigest: root,
      referencedObjectDigests: [child, root],
      protectionProofs: [proof("\uE000", child), proof("\u{10000}", root)],
      authority: { ...currentAuthority, purpose: "settlement" },
    });
    expect(committed.outcome.kind).toBe("workspace_committed");
  });

  it("allows exact settlement after ticket TTL when the renewable lease remains current", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-1",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    const currentAuthority = authority("long-running", digest("a"));
    const { prepared, leaseFence } = await preparedWrite(initial, currentAuthority, 2);
    const renewed = await applyWorkspaceCommand(prepared.state, {
      kind: "renew_write_lease",
      expectedEventSequence: prepared.state.eventSequence,
      now: 12,
      leaseFence,
      nextRenewalSequence: 1,
      requestedLeaseTtlMs: 500,
      authority: currentAuthority,
    });
    const root = digest("1");
    const committed = await applyWorkspaceCommand(renewed.state, {
      kind: "commit_workspace",
      expectedEventSequence: renewed.state.eventSequence,
      now: 20,
      materializationTicketId: "ticket-long-running",
      leaseFence,
      baseRevision: 0,
      workspaceCommitId: "commit-long-running",
      postExecutionRootDigest: root,
      referencedObjectDigests: [root],
      protectionProofs: [proof("proof-long-running", root)],
      authority: { ...currentAuthority, purpose: "settlement" },
    });
    expect(committed.outcome.kind).toBe("workspace_committed");
  });
});
