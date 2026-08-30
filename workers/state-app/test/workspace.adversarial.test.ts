import { describe, expect, it } from "vitest";

import type { Digest } from "@circulusd/protocol-types";

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

function authority(
  invocationId: string,
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
    effectService: "workspace",
    effectId: `effect-${invocationId}`,
    invocationId,
    requestDigest: digest("a"),
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
  state: WorkspaceAggregateState,
  invocationId: string,
  now: number,
  overrides: Partial<WorkspaceAuthoritySnapshot> = {},
) {
  return applyWorkspaceCommand(state, {
    kind: "acquire_write_lease",
    expectedEventSequence: state.eventSequence,
    now,
    authority: authority(invocationId, { workspaceId: state.workspaceId, ...overrides }),
    requestedLeaseId: `lease-${invocationId}`,
    sandboxId: `sandbox-${invocationId}`,
    backend: "nsjail",
    projectionGeneration: 1,
    requestedLeaseTtlMs: 100,
    requestedMaximumHoldMs: 500,
    acquireDeadline: 1_000,
    waitPolicy: "queue",
  });
}

async function acquiredLease(
  state: WorkspaceAggregateState,
  invocationId: string,
  now: number,
  authorityOverrides: Partial<WorkspaceAuthoritySnapshot> = {},
) {
  const result = await acquire(state, invocationId, now, authorityOverrides);
  if (result.outcome.kind !== "write_lease_acquired") {
    throw new Error("expected acquired lease");
  }
  return { ...result, lease: result.outcome.lease };
}

async function preparedWriter(
  authorityOverrides: Partial<WorkspaceAuthoritySnapshot> = {},
) {
  const initial = createWorkspaceState({
    workspaceId: "workspace-1",
    tenantId: "tenant-1",
    initialRootDigest: digest("0"),
  });
  const acquired = await acquiredLease(initial, "writer", 100, authorityOverrides);
  const leaseFence = fence(acquired.lease);
  const prepared = await applyWorkspaceCommand(acquired.state, {
    kind: "prepare_materialization",
    expectedEventSequence: acquired.state.eventSequence,
    now: 110,
    ticketId: "ticket-writer",
    accessMode: "read_write",
    requestedRevision: 0,
    authority: authority("writer", authorityOverrides),
    sandboxId: "sandbox-writer",
    backend: "nsjail",
    projectionGeneration: 1,
    leaseFence,
    ticketTtlMs: 500,
  });
  return { prepared, leaseFence };
}

describe("workspace adversarial contracts", () => {
  it("requires an authoritative protocol effect service before lease admission", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-1",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    const missingService = { ...authority("missing-service") } as Record<string, unknown>;
    Reflect.deleteProperty(missingService, "effectService");

    await expect(
      applyWorkspaceCommand(initial, {
        kind: "acquire_write_lease",
        expectedEventSequence: 0,
        now: 1,
        authority: missingService as unknown as WorkspaceAuthoritySnapshot,
        requestedLeaseId: "lease-missing-service",
        sandboxId: "sandbox-missing-service",
        backend: "nsjail",
        projectionGeneration: 1,
        requestedLeaseTtlMs: 100,
        requestedMaximumHoldMs: 500,
        acquireDeadline: 1_000,
        waitPolicy: "queue",
      }),
    ).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });

    await expect(
      applyWorkspaceCommand(initial, {
        kind: "acquire_write_lease",
        expectedEventSequence: 0,
        now: 1,
        authority: {
          ...authority("workspace-service"),
          effectService: "workspace",
        } as unknown as WorkspaceAuthoritySnapshot,
        requestedLeaseId: "lease-workspace-service",
        sandboxId: "sandbox-workspace-service",
        backend: "nsjail",
        projectionGeneration: 1,
        requestedLeaseTtlMs: 100,
        requestedMaximumHoldMs: 500,
        acquireDeadline: 1_000,
        waitPolicy: "queue",
      }),
    ).resolves.toMatchObject({ outcome: { kind: "write_lease_acquired" } });

    for (const effectService of ["model", "executor", "mcp", "artifact", "external-tool"]) {
      await expect(
        applyWorkspaceCommand(initial, {
          kind: "acquire_write_lease",
          expectedEventSequence: 0,
          now: 1,
          authority: {
            ...authority(`foreign-${effectService}`),
            effectService,
          } as unknown as WorkspaceAuthoritySnapshot,
          requestedLeaseId: `lease-foreign-${effectService}`,
          sandboxId: `sandbox-foreign-${effectService}`,
          backend: "nsjail",
          projectionGeneration: 1,
          requestedLeaseTtlMs: 100,
          requestedMaximumHoldMs: 500,
          acquireDeadline: 1_000,
          waitPolicy: "queue",
        }),
      ).resolves.toMatchObject({ outcome: { kind: "write_lease_acquired" } });
    }

    await expect(
      applyWorkspaceCommand(initial, {
        kind: "acquire_write_lease",
        expectedEventSequence: 0,
        now: 1,
        authority: {
          ...authority("unknown-service"),
          effectService: "unknown",
        } as unknown as WorkspaceAuthoritySnapshot,
        requestedLeaseId: "lease-unknown-service",
        sandboxId: "sandbox-unknown-service",
        backend: "nsjail",
        projectionGeneration: 1,
        requestedLeaseTtlMs: 100,
        requestedMaximumHoldMs: 500,
        acquireDeadline: 1_000,
        waitPolicy: "queue",
      }),
    ).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });

    expect(initial).toMatchObject({ eventSequence: 0, activeWriteLease: null, writeQueue: [] });
  });

  it("allows an executor effect to prepare read-only materialization", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-1",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });

    await expect(
      applyWorkspaceCommand(initial, {
        kind: "prepare_materialization",
        expectedEventSequence: 0,
        now: 1,
        ticketId: "ticket-executor-reader",
        accessMode: "read_only",
        requestedRevision: 0,
        authority: {
          ...authority("executor-reader", {
            effectivePermissions: ["workspace.read"],
          }),
          effectService: "executor",
        } as unknown as WorkspaceAuthoritySnapshot,
        sandboxId: "sandbox-executor-reader",
        backend: "nsjail",
        projectionGeneration: 1,
        leaseFence: null,
        ticketTtlMs: 100,
      }),
    ).resolves.toMatchObject({ outcome: { kind: "materialization_prepared" } });
    expect(initial.materializationTickets).toEqual([]);
  });

  it("does not let a read-only authority acquire writer authority", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-1",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });

    await expect(
      acquire(initial, "reader", 1, { effectivePermissions: ["workspace.read"] }),
    ).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
  });

  it("rejects forged workspace scope and every rotated current authority fence", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-authority",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    await expect(
      applyWorkspaceCommand(initial, {
        kind: "acquire_write_lease",
        expectedEventSequence: 0,
        now: 1,
        authority: authority("forged"),
        requestedLeaseId: "lease-forged",
        sandboxId: "sandbox-forged",
        backend: "nsjail",
        projectionGeneration: 1,
        requestedLeaseTtlMs: 100,
        requestedMaximumHoldMs: 500,
        acquireDeadline: 1_000,
        waitPolicy: "queue",
      }),
    ).rejects.toMatchObject({ code: "PERMISSION_DENIED" });

    const owner = await acquiredLease(initial, "owner", 2);
    const leaseFence = fence(owner.lease);
    const rotations: Partial<WorkspaceAuthoritySnapshot>[] = [
      { turnLeaseGeneration: 2 },
      { placementGeneration: 2 },
      { sandboxGeneration: 2 },
      { authorizationGeneration: 2 },
      { runtimeRevision: "runtime-2" },
      { policySnapshotDigest: digest("c") },
      { emergencyOverlayDigest: digest("b") },
    ];
    for (const rotation of rotations) {
      await expect(
        applyWorkspaceCommand(owner.state, {
          kind: "renew_write_lease",
          expectedEventSequence: owner.state.eventSequence,
          now: 10,
          leaseFence,
          nextRenewalSequence: 1,
          requestedLeaseTtlMs: 100,
          authority: authority("owner", {
            workspaceId: initial.workspaceId,
            ...rotation,
          }),
        }),
      ).rejects.toMatchObject({ code: "STALE_GENERATION" });
    }

    await expect(
      applyWorkspaceCommand(owner.state, {
        kind: "renew_write_lease",
        expectedEventSequence: owner.state.eventSequence,
        now: 10,
        leaseFence,
        nextRenewalSequence: 1,
        requestedLeaseTtlMs: 100,
        authority: authority("owner", {
          workspaceId: initial.workspaceId,
          expiresAt: 15_000,
        }),
      }),
    ).resolves.toMatchObject({ outcome: { kind: "write_lease_renewed" } });
  });

  it("preserves an admitted FIFO waiter past authority TTL until its acquire deadline", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-fifo",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    const owner = await acquiredLease(initial, "owner", 1);
    const queued = await acquire(owner.state, "waiter", 2, { expiresAt: 50 });

    const released = await applyWorkspaceCommand(queued.state, {
      kind: "release_write_lease",
      expectedEventSequence: queued.state.eventSequence,
      now: 100,
      leaseFence: fence(owner.lease),
      authority: authority("owner", { workspaceId: initial.workspaceId }),
    });

    expect(released.outcome).toMatchObject({
      kind: "write_lease_released",
      promotedInvocationId: null,
    });
    expect(released.state.activeWriteLease).toBeNull();
    expect(released.state.writeQueue[0]).toMatchObject({
      authority: { invocationId: "waiter" },
      enqueueSequence: 1,
    });

    const granted = await acquire(released.state, "waiter", 101, {
      issuedAt: 100,
      expiresAt: 1_000,
    });
    expect(granted.outcome).toMatchObject({
      kind: "write_lease_acquired",
      lease: { invocationId: "waiter", enqueueSequence: 1 },
    });
  });

  it("does not allocate a second FIFO sequence for the same terminal dispatch attempt", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-fifo-retry",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    const owner = await acquiredLease(initial, "owner", 1);
    const queued = await acquire(owner.state, "waiter", 2);
    const cancelled = await applyWorkspaceCommand(queued.state, {
      kind: "cancel_write_lease_request",
      expectedEventSequence: queued.state.eventSequence,
      now: 3,
      invocationId: "waiter",
      requestDigest: digest("a"),
      authority: authority("waiter", { workspaceId: initial.workspaceId }),
    });

    await expect(
      applyWorkspaceCommand(cancelled.state, {
        kind: "acquire_write_lease",
        expectedEventSequence: cancelled.state.eventSequence,
        now: 4,
        authority: authority("waiter", { workspaceId: initial.workspaceId }),
        requestedLeaseId: "lease-waiter-retry",
        sandboxId: "sandbox-waiter",
        backend: "nsjail",
        projectionGeneration: 1,
        requestedLeaseTtlMs: 100,
        requestedMaximumHoldMs: 500,
        acquireDeadline: 1_000,
        waitPolicy: "queue",
      }),
    ).rejects.toMatchObject({ code: "STALE_GENERATION" });
    expect(cancelled.state.nextLeaseEnqueueSequence).toBe(2);
  });

  it("does not relabel a released invocation effect on the next dispatch attempt", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-retry-service",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    const acquired = await acquiredLease(initial, "retry-service", 1, {
      effectService: "executor",
    });
    const released = await applyWorkspaceCommand(acquired.state, {
      kind: "release_write_lease",
      expectedEventSequence: acquired.state.eventSequence,
      now: 2,
      leaseFence: fence(acquired.lease),
      authority: authority("retry-service", {
        workspaceId: initial.workspaceId,
        effectService: "executor",
      }),
    });

    await expect(
      applyWorkspaceCommand(released.state, {
        kind: "acquire_write_lease",
        expectedEventSequence: released.state.eventSequence,
        now: 3,
        authority: authority("retry-service", {
          workspaceId: initial.workspaceId,
          effectService: "workspace",
          dispatchAttempt: 2,
        }),
        requestedLeaseId: "lease-retry-service-2",
        sandboxId: "sandbox-retry-service",
        backend: "nsjail",
        projectionGeneration: 2,
        requestedLeaseTtlMs: 100,
        requestedMaximumHoldMs: 500,
        acquireDeadline: 1_000,
        waitPolicy: "queue",
      }),
    ).rejects.toMatchObject({ code: "STALE_GENERATION" });
    await expect(
      applyWorkspaceCommand(released.state, {
        kind: "acquire_write_lease",
        expectedEventSequence: released.state.eventSequence,
        now: 3,
        authority: authority("retry-service", {
          workspaceId: initial.workspaceId,
          effectService: "executor",
          effectId: "effect-retry-service-replaced",
          dispatchAttempt: 2,
        }),
        requestedLeaseId: "lease-retry-service-2",
        sandboxId: "sandbox-retry-service",
        backend: "nsjail",
        projectionGeneration: 2,
        requestedLeaseTtlMs: 100,
        requestedMaximumHoldMs: 500,
        acquireDeadline: 1_000,
        waitPolicy: "queue",
      }),
    ).rejects.toMatchObject({ code: "STALE_GENERATION" });
  });

  it("does not relabel a conflict-only invocation effect on the next dispatch attempt", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-conflict-service",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    const owner = await acquiredLease(initial, "owner", 1);
    const conflicted = await applyWorkspaceCommand(owner.state, {
      kind: "acquire_write_lease",
      expectedEventSequence: owner.state.eventSequence,
      now: 2,
      authority: authority("conflict-service", {
        workspaceId: initial.workspaceId,
        effectService: "executor",
      }),
      requestedLeaseId: "lease-conflict-service-1",
      sandboxId: "sandbox-conflict-service",
      backend: "nsjail",
      projectionGeneration: 1,
      requestedLeaseTtlMs: 100,
      requestedMaximumHoldMs: 500,
      acquireDeadline: 1_000,
      waitPolicy: "fail",
    });
    expect(conflicted.outcome.kind).toBe("write_lease_conflict");

    await expect(
      applyWorkspaceCommand(conflicted.state, {
        kind: "acquire_write_lease",
        expectedEventSequence: conflicted.state.eventSequence,
        now: 3,
        authority: authority("conflict-service", {
          workspaceId: initial.workspaceId,
          effectService: "workspace",
          dispatchAttempt: 2,
        }),
        requestedLeaseId: "lease-conflict-service-2",
        sandboxId: "sandbox-conflict-service",
        backend: "nsjail",
        projectionGeneration: 2,
        requestedLeaseTtlMs: 100,
        requestedMaximumHoldMs: 500,
        acquireDeadline: 1_000,
        waitPolicy: "fail",
      }),
    ).rejects.toMatchObject({ code: "STALE_GENERATION" });
    await expect(
      applyWorkspaceCommand(conflicted.state, {
        kind: "acquire_write_lease",
        expectedEventSequence: conflicted.state.eventSequence,
        now: 3,
        authority: authority("conflict-service", {
          workspaceId: initial.workspaceId,
          effectService: "executor",
          effectId: "effect-conflict-service-replaced",
          dispatchAttempt: 2,
        }),
        requestedLeaseId: "lease-conflict-service-2",
        sandboxId: "sandbox-conflict-service",
        backend: "nsjail",
        projectionGeneration: 2,
        requestedLeaseTtlMs: 100,
        requestedMaximumHoldMs: 500,
        acquireDeadline: 1_000,
        waitPolicy: "fail",
      }),
    ).rejects.toMatchObject({ code: "STALE_GENERATION" });
  });

  it("keeps a write materialization usable while its lease is validly renewed", async () => {
    const { prepared, leaseFence } = await preparedWriter();
    const renewed = await applyWorkspaceCommand(prepared.state, {
      kind: "renew_write_lease",
      expectedEventSequence: prepared.state.eventSequence,
      now: 150,
      leaseFence,
      nextRenewalSequence: 1,
      requestedLeaseTtlMs: 500,
      authority: authority("writer", {
        issuedAt: 140,
        expiresAt: 200,
        turnLeaseExpiresAt: 300,
      }),
    });
    expect(renewed.state.activeWriteLease?.expiresAt).toBe(300);
    expect(renewed.state.materializationTickets[0]).toMatchObject({
      expiresAt: 300,
      admissionAuthority: { turnLeaseExpiresAt: 300 },
    });

    await expect(
      applyWorkspaceCommand(renewed.state, {
        kind: "commit_workspace",
        expectedEventSequence: renewed.state.eventSequence,
        now: 250,
        materializationTicketId: "ticket-writer",
        leaseFence,
        baseRevision: 0,
        workspaceCommitId: "commit-writer",
        postExecutionRootDigest: digest("1"),
        referencedObjectDigests: [digest("1")],
        protectionProofs: [protectionProof("protect-root", digest("1"))],
        authority: {
          ...authority("writer"),
          purpose: "settlement",
          turnStatus: "settling",
          expiresAt: 160,
        },
      }),
    ).resolves.toMatchObject({ outcome: { kind: "workspace_committed" } });
  });

  it("rejects a new root without a typed protection proof", async () => {
    const { prepared, leaseFence } = await preparedWriter();

    await expect(
      applyWorkspaceCommand(prepared.state, {
        kind: "commit_workspace",
        expectedEventSequence: prepared.state.eventSequence,
        now: 120,
        materializationTicketId: "ticket-writer",
        leaseFence,
        baseRevision: 0,
        workspaceCommitId: "commit-unprotected",
        postExecutionRootDigest: digest("1"),
        referencedObjectDigests: [digest("1")],
        protectionProofs: [],
        authority: { ...authority("writer"), purpose: "settlement" },
      }),
    ).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });

    await expect(
      applyWorkspaceCommand(prepared.state, {
        kind: "commit_workspace",
        expectedEventSequence: prepared.state.eventSequence,
        now: 120,
        materializationTicketId: "ticket-writer",
        leaseFence,
        baseRevision: 0,
        workspaceCommitId: "commit-wrong-root-proof",
        postExecutionRootDigest: digest("1"),
        referencedObjectDigests: [digest("1")],
        protectionProofs: [protectionProof("protect-other", digest("2"))],
        authority: { ...authority("writer"), purpose: "settlement" },
      }),
    ).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });

    await expect(
      applyWorkspaceCommand(prepared.state, {
        kind: "commit_workspace",
        expectedEventSequence: prepared.state.eventSequence,
        now: 120,
        materializationTicketId: "ticket-writer",
        leaseFence,
        baseRevision: 0,
        workspaceCommitId: "commit-foreign-proof",
        postExecutionRootDigest: digest("1"),
        referencedObjectDigests: [digest("1")],
        protectionProofs: [
          { ...protectionProof("protect-foreign", digest("1")), tenantId: "tenant-2" },
        ],
        authority: { ...authority("writer"), purpose: "settlement" },
      }),
    ).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
  });

  it("does not create a missing workspace commit from externally-committed authority", async () => {
    const { prepared, leaseFence } = await preparedWriter();

    await expect(
      applyWorkspaceCommand(prepared.state, {
        kind: "commit_workspace",
        expectedEventSequence: prepared.state.eventSequence,
        now: 120,
        materializationTicketId: "ticket-writer",
        leaseFence,
        baseRevision: 0,
        workspaceCommitId: "commit-missing-ledger",
        postExecutionRootDigest: digest("1"),
        referencedObjectDigests: [digest("1")],
        protectionProofs: [protectionProof("protect-root", digest("1"))],
        authority: {
          ...authority("writer"),
          purpose: "settlement",
          effectStatus: "externally_committed",
        },
      }),
    ).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
  });

  it("authenticates a committed-ledger replay before returning the old result", async () => {
    const { prepared, leaseFence } = await preparedWriter();
    const committed = await applyWorkspaceCommand(prepared.state, {
      kind: "commit_workspace",
      expectedEventSequence: prepared.state.eventSequence,
      now: 120,
      materializationTicketId: "ticket-writer",
      leaseFence,
      baseRevision: 0,
      workspaceCommitId: "commit-writer",
      postExecutionRootDigest: digest("1"),
      referencedObjectDigests: [digest("1")],
      protectionProofs: [protectionProof("protect-root", digest("1"))],
      authority: { ...authority("writer"), purpose: "settlement" },
    });

    await expect(
      applyWorkspaceCommand(committed.state, {
        kind: "commit_workspace",
        expectedEventSequence: 0,
        now: 121,
        materializationTicketId: "ticket-writer",
        leaseFence: { ...leaseFence, sessionId: "session-attacker" },
        baseRevision: 0,
        workspaceCommitId: "commit-writer",
        postExecutionRootDigest: digest("1"),
        referencedObjectDigests: [digest("1")],
        protectionProofs: [protectionProof("protect-root", digest("1"))],
        authority: { ...authority("writer"), purpose: "settlement" },
      }),
    ).rejects.toMatchObject({ code: "STALE_GENERATION" });

    await expect(
      applyWorkspaceCommand(committed.state, {
        kind: "commit_workspace",
        expectedEventSequence: 0,
        now: 121,
        materializationTicketId: "ticket-writer",
        leaseFence,
        baseRevision: 0,
        workspaceCommitId: "commit-writer",
        postExecutionRootDigest: digest("2"),
        referencedObjectDigests: [digest("2")],
        protectionProofs: [protectionProof("protect-other-root", digest("2"))],
        authority: { ...authority("writer"), purpose: "settlement" },
      }),
    ).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
  });

  it("allows executor commit replay but reserves ledger recovery for workspace effects", async () => {
    const { prepared, leaseFence } = await preparedWriter({
      effectService: "executor",
    });
    const executorSettlement: WorkspaceAuthoritySnapshot = {
      ...authority("writer"),
      purpose: "settlement",
      effectService: "executor",
    };

    const committed = await applyWorkspaceCommand(prepared.state, {
      kind: "commit_workspace",
      expectedEventSequence: prepared.state.eventSequence,
      now: 120,
      materializationTicketId: "ticket-writer",
      leaseFence,
      baseRevision: 0,
      workspaceCommitId: "commit-executor",
      postExecutionRootDigest: digest("1"),
      referencedObjectDigests: [digest("1")],
      protectionProofs: [protectionProof("protect-executor", digest("1"))],
      authority: executorSettlement,
    });

    const replayed = await applyWorkspaceCommand(committed.state, {
      kind: "commit_workspace",
      expectedEventSequence: committed.state.eventSequence,
      now: 121,
      materializationTicketId: "ticket-writer",
      leaseFence,
      baseRevision: 0,
      workspaceCommitId: "commit-executor",
      postExecutionRootDigest: digest("1"),
      referencedObjectDigests: [digest("1")],
      protectionProofs: [protectionProof("protect-executor", digest("1"))],
      authority: executorSettlement,
    });
    expect(replayed).toMatchObject({
      replayed: true,
      outcome: { kind: "workspace_committed" },
    });
    await expect(
      applyWorkspaceCommand(committed.state, {
        kind: "commit_workspace",
        expectedEventSequence: committed.state.eventSequence,
        now: 121,
        materializationTicketId: "ticket-writer",
        leaseFence,
        baseRevision: 0,
        workspaceCommitId: "commit-executor",
        postExecutionRootDigest: digest("1"),
        referencedObjectDigests: [digest("1")],
        protectionProofs: [protectionProof("protect-executor", digest("1"))],
        authority: { ...executorSettlement, effectService: "workspace" },
      }),
    ).rejects.toMatchObject({ code: "STALE_GENERATION" });
    expect(() =>
      lookupWorkspaceInvocation(
        committed.state,
        "writer",
        digest("a"),
        executorSettlement,
        121,
      ),
    ).toThrowError(expect.objectContaining({ code: "PERMISSION_DENIED" }));
  });

  it("validates the complete request before replaying a materialization ticket", async () => {
    const { prepared, leaseFence } = await preparedWriter();

    await expect(
      applyWorkspaceCommand(prepared.state, {
        kind: "prepare_materialization",
        expectedEventSequence: 0,
        now: 111,
        ticketId: "ticket-writer",
        accessMode: "read_write",
        requestedRevision: 0,
        authority: authority("writer", { authorizationGeneration: 2 }),
        sandboxId: "sandbox-writer",
        backend: "nsjail",
        projectionGeneration: 1,
        leaseFence,
        ticketTtlMs: 500,
      }),
    ).rejects.toMatchObject({ code: "STALE_GENERATION" });

    await expect(
      applyWorkspaceCommand(prepared.state, {
        kind: "prepare_materialization",
        expectedEventSequence: 0,
        now: 111,
        ticketId: "ticket-writer",
        accessMode: "read_write",
        requestedRevision: 0,
        authority: authority("writer"),
        sandboxId: "sandbox-writer",
        backend: "nsjail",
        projectionGeneration: 1,
        leaseFence: null,
        ticketTtlMs: 999,
      }),
    ).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
  });

  it("rejects a revision that lost its matching invocation ledger record", async () => {
    const { prepared, leaseFence } = await preparedWriter();
    const committed = await applyWorkspaceCommand(prepared.state, {
      kind: "commit_workspace",
      expectedEventSequence: prepared.state.eventSequence,
      now: 120,
      materializationTicketId: "ticket-writer",
      leaseFence,
      baseRevision: 0,
      workspaceCommitId: "commit-writer",
      postExecutionRootDigest: digest("1"),
      referencedObjectDigests: [digest("1")],
      protectionProofs: [protectionProof("protect-root", digest("1"))],
      authority: { ...authority("writer"), purpose: "settlement" },
    });
    const corrupted = structuredClone(committed.state);
    corrupted.invocationLedger = [];

    expect(() => assertWorkspaceInvariants(corrupted)).toThrowError(
      expect.objectContaining({ code: "FAILED_PRECONDITION" }),
    );
  });

  it("fails closed with a workspace error when a state collection is not an array", () => {
    const corrupted = createWorkspaceState({
      workspaceId: "workspace-malformed-array",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    }) as Omit<WorkspaceAggregateState, "revisions"> & { revisions: unknown };
    corrupted.revisions = null;

    expect(() =>
      assertWorkspaceInvariants(corrupted as unknown as WorkspaceAggregateState),
    ).toThrowError(expect.objectContaining({ code: "INVALID_ARGUMENT" }));
  });

  it("rotates authority-bearing workspace state and command schemas", () => {
    expect(WORKSPACE_STATE_SCHEMA_VERSION).toBe(2);
    expect(WORKSPACE_COMMAND_SCHEMA_VERSION).toBe(2);
    const legacy = createWorkspaceState({
      workspaceId: "workspace-legacy-schema",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    }) as unknown as { schemaVersion: number };
    legacy.schemaVersion = 1;

    expect(() =>
      assertWorkspaceInvariants(legacy as unknown as WorkspaceAggregateState),
    ).toThrowError(expect.objectContaining({ code: "FAILED_PRECONDITION" }));
  });

  it("rejects a stored invalid effect service before internal promotion", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-1",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    const owner = await acquiredLease(initial, "owner", 1);
    const queued = await acquire(owner.state, "waiter", 2);
    const corrupted = structuredClone(queued.state);
    const queuedAuthority = corrupted.writeQueue[0]?.authority as unknown as Record<
      string,
      unknown
    >;
    queuedAuthority.effectService = "unknown";

    await expect(
      applyWorkspaceCommand(corrupted, {
        kind: "reconcile_write_queue",
        expectedEventSequence: corrupted.eventSequence,
        now: 3,
      }),
    ).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
    expect(corrupted.activeWriteLease?.invocationId).toBe("owner");
    expect(corrupted.writeQueue).toHaveLength(1);
  });

  it("copies current authority snapshots instead of aliasing caller-owned objects", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-authority-copy",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    const supplied = structuredClone(
      authority("authority-copy", { workspaceId: initial.workspaceId }),
    ) as { -readonly [Key in keyof WorkspaceAuthoritySnapshot]: WorkspaceAuthoritySnapshot[Key] };
    const acquired = await applyWorkspaceCommand(initial, {
      kind: "acquire_write_lease",
      expectedEventSequence: 0,
      now: 1,
      authority: supplied,
      requestedLeaseId: "lease-authority-copy",
      sandboxId: "sandbox-authority-copy",
      backend: "nsjail",
      projectionGeneration: 1,
      requestedLeaseTtlMs: 100,
      requestedMaximumHoldMs: 500,
      acquireDeadline: 1_000,
      waitPolicy: "queue",
    });

    supplied.authorizationGeneration = 99;

    expect(acquired.state.activeWriteLease?.admissionAuthority.authorizationGeneration).toBe(1);
    expect(() => assertWorkspaceInvariants(acquired.state)).not.toThrow();
  });

  it("caps admission lifetimes and requires current authority before granting an admitted waiter", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-turn-deadline",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    const owner = await acquiredLease(initial, "owner", 1);
    const queued = await acquire(owner.state, "waiter", 2, {
      expiresAt: 500,
      turnLeaseExpiresAt: 50,
    });
    const released = await applyWorkspaceCommand(queued.state, {
      kind: "release_write_lease",
      expectedEventSequence: queued.state.eventSequence,
      now: 100,
      leaseFence: fence(owner.lease),
      authority: authority("owner", { workspaceId: initial.workspaceId }),
    });

    expect(released.state.activeWriteLease).toBeNull();
    expect(released.state.writeQueue[0]).toMatchObject({
      authority: { invocationId: "waiter" },
      enqueueSequence: 1,
    });
    expect(
      released.state.leaseHistory.find((record) => record.invocationId === "waiter"),
    ).toMatchObject({ status: "queued", latestEnqueueSequence: 1 });

    const refreshed = await acquire(released.state, "waiter", 101, {
      issuedAt: 100,
      expiresAt: 500,
      turnLeaseExpiresAt: 500,
    });
    expect(refreshed.outcome).toMatchObject({
      kind: "write_lease_acquired",
      lease: { invocationId: "waiter", enqueueSequence: 1, expiresAt: 201 },
    });

    const direct = await acquire(initial, "short-turn", 10, {
      expiresAt: 500,
      turnLeaseExpiresAt: 50,
    });
    expect(direct.state.activeWriteLease?.expiresAt).toBe(50);

    const readTicket = await applyWorkspaceCommand(initial, {
      kind: "prepare_materialization",
      expectedEventSequence: 0,
      now: 10,
      ticketId: "ticket-short-turn",
      accessMode: "read_only",
      requestedRevision: 0,
      authority: authority("short-read", {
        workspaceId: initial.workspaceId,
        effectivePermissions: ["workspace.read"],
        expiresAt: 500,
        turnLeaseExpiresAt: 50,
      }),
      sandboxId: "sandbox-short-read",
      backend: "nsjail",
      projectionGeneration: 1,
      leaseFence: null,
      ticketTtlMs: 100,
    });
    expect(readTicket.state.materializationTickets[0]?.expiresAt).toBe(50);
  });

  it("rejects unknown fields inside a lease fence", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-fence-shape",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });
    const acquired = await acquiredLease(initial, "owner", 1);

    await expect(
      applyWorkspaceCommand(acquired.state, {
        kind: "renew_write_lease",
        expectedEventSequence: acquired.state.eventSequence,
        now: 2,
        leaseFence: { ...fence(acquired.lease), unexpected: true } as never,
        nextRenewalSequence: 1,
        requestedLeaseTtlMs: 100,
        authority: authority("owner", { workspaceId: initial.workspaceId }),
      }),
    ).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
  });

  it("fails closed on unknown command fields and kinds", async () => {
    expect(() =>
      createWorkspaceState({
        workspaceId: "workspace-create-shape",
        tenantId: "tenant-1",
        initialRootDigest: digest("0"),
        unexpected: true,
      } as never),
    ).toThrowError(expect.objectContaining({ code: "INVALID_ARGUMENT" }));

    const initial = createWorkspaceState({
      workspaceId: "workspace-shape",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });

    await expect(
      applyWorkspaceCommand(initial, {
        kind: "reconcile_write_queue",
        expectedEventSequence: 0,
        now: 1,
        unexpected: true,
      } as never),
    ).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
    await expect(
      applyWorkspaceCommand(initial, {
        kind: "unknown_workspace_command",
        expectedEventSequence: 0,
        now: 1,
      } as never),
    ).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
  });

  it("keeps cross-collection invariant comparisons linear as history grows", async () => {
    let current = createWorkspaceState({
      workspaceId: "workspace-linear-invariants",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });

    for (let index = 1; index <= 12; index += 1) {
      const invocationId = `committed-${index}`;
      const acquired = await acquiredLease(current, invocationId, index * 10);
      const leaseFence = fence(acquired.lease);
      const ticketId = `ticket-${invocationId}`;
      const nextRootDigest = digest(index.toString(16));
      const prepared = await applyWorkspaceCommand(acquired.state, {
        kind: "prepare_materialization",
        expectedEventSequence: acquired.state.eventSequence,
        now: index * 10 + 1,
        ticketId,
        accessMode: "read_write",
        requestedRevision: current.revision,
        authority: authority(invocationId, { workspaceId: current.workspaceId }),
        sandboxId: `sandbox-${invocationId}`,
        backend: "nsjail",
        projectionGeneration: 1,
        leaseFence,
        ticketTtlMs: 50,
      });
      const committed = await applyWorkspaceCommand(prepared.state, {
        kind: "commit_workspace",
        expectedEventSequence: prepared.state.eventSequence,
        now: index * 10 + 2,
        materializationTicketId: ticketId,
        leaseFence,
        baseRevision: current.revision,
        workspaceCommitId: `workspace-commit-${index}`,
        postExecutionRootDigest: nextRootDigest,
        referencedObjectDigests: [nextRootDigest],
        protectionProofs: [
          protectionProof(`protect-${index}`, nextRootDigest),
        ],
        authority: authority(invocationId, {
          purpose: "settlement",
          workspaceId: current.workspaceId,
        }),
      });
      current = committed.state;
    }

    const owner = await acquiredLease(current, "active-owner", 300);
    current = owner.state;
    for (let index = 1; index <= 16; index += 1) {
      const queued = await acquire(current, `queued-${index}`, 300 + index);
      expect(queued.outcome.kind).toBe("write_lease_queued");
      current = queued.state;
    }

    let relationalComparisons = 0;
    const instrumentedArrayPrototype = Object.create(Array.prototype) as unknown[];
    Object.defineProperties(instrumentedArrayPrototype, {
      find: {
        configurable: true,
        value: function (
          this: unknown[],
          predicate: (value: unknown, index: number, array: unknown[]) => unknown,
          thisArgument?: unknown,
        ): unknown {
          for (let index = 0; index < this.length; index += 1) {
            if (!(index in this)) {
              continue;
            }
            relationalComparisons += 1;
            const value = this[index];
            if (predicate.call(thisArgument, value, index, this)) {
              return value;
            }
          }
          return undefined;
        },
      },
      some: {
        configurable: true,
        value: function (
          this: unknown[],
          predicate: (value: unknown, index: number, array: unknown[]) => unknown,
          thisArgument?: unknown,
        ): boolean {
          for (let index = 0; index < this.length; index += 1) {
            if (!(index in this)) {
              continue;
            }
            relationalComparisons += 1;
            if (predicate.call(thisArgument, this[index], index, this)) {
              return true;
            }
          }
          return false;
        },
      },
    });
    const historyPrototype = Object.getPrototypeOf(current.leaseHistory);
    const ledgerPrototype = Object.getPrototypeOf(current.invocationLedger);
    Object.setPrototypeOf(current.leaseHistory, instrumentedArrayPrototype);
    Object.setPrototypeOf(current.invocationLedger, instrumentedArrayPrototype);
    try {
      expect(() => assertWorkspaceInvariants(current)).not.toThrow();
    } finally {
      Object.setPrototypeOf(current.leaseHistory, historyPrototype);
      Object.setPrototypeOf(current.invocationLedger, ledgerPrototype);
    }

    expect(relationalComparisons).toBeLessThanOrEqual(
      4 * (current.leaseHistory.length + current.invocationLedger.length),
    );
  });
});
