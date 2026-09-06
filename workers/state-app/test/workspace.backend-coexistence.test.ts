import { describe, expect, it } from "vitest";

import type { Digest } from "@circulusd/protocol-types";

import {
  applyWorkspaceCommand,
  createWorkspaceState,
  type WorkspaceAggregateState,
  type WorkspaceAuthoritySnapshot,
  type WorkspaceLeaseFence,
  type WorkspaceProtectionProof,
  type WorkspaceWriteLease,
} from "../src/workspace/index.ts";

// Reference-first evidence for SPEC §53.13 (Backend coexistence/switch) at the
// Workspace-authority level: the durable Workspace aggregate holds exactly one
// mutable write lease regardless of which execution backend requests it, lets
// different backends read one shared workspace concurrently, and exposes the
// latest committed revision to whichever backend acquires next. This proves the
// cross-backend authority LOGIC host-independently; it promotes nothing. The
// real three-provider integration and the cache-key network/environment/
// security-class reuse rules (§53.13 bullets 4-5) remain external and are the
// subject of the sandbox conformance gates (internal/conformance/{nsjail,docker,
// firecracker}), so §53.13 stays NOT_RUN.

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
    effectOperation: "workspace.commit",
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
  options: { readonly now: number; readonly leaseId: string; readonly waitPolicy?: "queue" | "fail" },
) {
  return applyWorkspaceCommand(state, {
    kind: "acquire_write_lease",
    expectedEventSequence: state.eventSequence,
    now: options.now,
    authority: currentAuthority,
    requestedLeaseId: options.leaseId,
    sandboxId: currentAuthority.sandboxId,
    backend: currentAuthority.backend,
    projectionGeneration: 1,
    requestedLeaseTtlMs: 1_000,
    requestedMaximumHoldMs: 2_000,
    acquireDeadline: 4_000,
    waitPolicy: options.waitPolicy ?? "queue",
  });
}

async function readOnly(
  state: WorkspaceAggregateState,
  currentAuthority: WorkspaceAuthoritySnapshot,
  options: { readonly now: number; readonly ticketId: string; readonly requestedRevision: number },
) {
  return applyWorkspaceCommand(state, {
    kind: "prepare_materialization",
    expectedEventSequence: state.eventSequence,
    now: options.now,
    ticketId: options.ticketId,
    accessMode: "read_only",
    requestedRevision: options.requestedRevision,
    authority: { ...currentAuthority, effectivePermissions: ["workspace.read"] },
    sandboxId: currentAuthority.sandboxId,
    backend: currentAuthority.backend,
    projectionGeneration: 1,
    leaseFence: null,
    ticketTtlMs: 500,
  });
}

describe("workspace backend coexistence (SPEC §53.13)", () => {
  it("lets different backends read one shared workspace concurrently", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-1",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });

    const readerNsjail = await readOnly(
      initial,
      authority("reader-nsjail", digest("a"), { backend: "nsjail" }),
      { now: 1, ticketId: "ticket-nsjail-read", requestedRevision: 0 },
    );
    expect(readerNsjail.outcome).toMatchObject({
      kind: "materialization_prepared",
      ticket: { accessMode: "read_only", revision: 0, rootDigest: digest("0"), backend: "nsjail" },
    });

    const readerDocker = await readOnly(
      readerNsjail.state,
      authority("reader-docker", digest("b"), { backend: "docker" }),
      { now: 2, ticketId: "ticket-docker-read", requestedRevision: 0 },
    );
    expect(readerDocker.outcome).toMatchObject({
      kind: "materialization_prepared",
      ticket: { accessMode: "read_only", revision: 0, rootDigest: digest("0"), backend: "docker" },
    });

    // Reads never touch the single mutable lease; both backends observe the
    // same committed revision 0 concurrently.
    expect(readerDocker.state.activeWriteLease).toBeNull();
    expect(readerDocker.state.materializationTickets.map((ticket) => ticket.backend).sort()).toEqual([
      "docker",
      "nsjail",
    ]);
  });

  it("shares one mutable lease across backends and hands the latest committed revision to the next backend", async () => {
    const initial = createWorkspaceState({
      workspaceId: "workspace-1",
      tenantId: "tenant-1",
      initialRootDigest: digest("0"),
    });

    // Session A (nsjail) takes the single mutable write lease.
    const writerNsjail = authority("writer-nsjail", digest("a"), { backend: "nsjail" });
    const acquiredA = await acquire(initial, writerNsjail, { now: 1, leaseId: "lease-nsjail" });
    if (acquiredA.outcome.kind !== "write_lease_acquired") {
      throw new Error("expected the nsjail writer to acquire the lease");
    }
    const leaseFenceA = fence(acquiredA.outcome.lease);
    const preparedA = await applyWorkspaceCommand(acquiredA.state, {
      kind: "prepare_materialization",
      expectedEventSequence: acquiredA.state.eventSequence,
      now: 2,
      ticketId: "ticket-nsjail-write",
      accessMode: "read_write",
      requestedRevision: 0,
      authority: writerNsjail,
      sandboxId: writerNsjail.sandboxId,
      backend: "nsjail",
      projectionGeneration: 1,
      leaseFence: leaseFenceA,
      ticketTtlMs: 500,
    });

    // Session B (docker) cannot take a second mutable lease on the same
    // workspace while nsjail holds it — there is exactly one.
    const contenderDocker = authority("contender-docker", digest("b"), { backend: "docker" });
    const conflicted = await acquire(preparedA.state, contenderDocker, {
      now: 3,
      leaseId: "lease-docker-contender",
      waitPolicy: "fail",
    });
    expect(conflicted.outcome).toMatchObject({
      kind: "write_lease_conflict",
      holderSessionId: "session-writer-nsjail",
    });

    // Session A commits a new revision and the commit releases the lease.
    const committedRoot = digest("1");
    const committedA = await applyWorkspaceCommand(conflicted.state, {
      kind: "commit_workspace",
      expectedEventSequence: conflicted.state.eventSequence,
      now: 4,
      materializationTicketId: "ticket-nsjail-write",
      leaseFence: leaseFenceA,
      baseRevision: 0,
      workspaceCommitId: "commit-nsjail",
      postExecutionRootDigest: committedRoot,
      referencedObjectDigests: [committedRoot],
      protectionProofs: [proof("proof-nsjail", committedRoot)],
      authority: { ...writerNsjail, purpose: "settlement" },
    });
    expect(committedA.outcome.kind).toBe("workspace_committed");
    expect(committedA.state.activeWriteLease).toBeNull();
    expect(committedA.state.revisions).toHaveLength(2);

    // Session D (docker) reads and sees the latest committed revision 1.
    const readerDocker = await readOnly(
      committedA.state,
      authority("reader-docker", digest("c"), { backend: "docker" }),
      { now: 5, ticketId: "ticket-docker-read-latest", requestedRevision: 1 },
    );
    expect(readerDocker.outcome).toMatchObject({
      kind: "materialization_prepared",
      ticket: { accessMode: "read_only", revision: 1, rootDigest: committedRoot, backend: "docker" },
    });

    // The single mutable lease is now available to a different backend.
    const writerDocker = authority("writer-docker", digest("e"), { backend: "docker" });
    const acquiredC = await acquire(readerDocker.state, writerDocker, {
      now: 6,
      leaseId: "lease-docker",
    });
    expect(acquiredC.outcome).toMatchObject({
      kind: "write_lease_acquired",
      lease: { backend: "docker", baseRevision: 1 },
    });
  });
});
