import type { Digest, ReplayPolicy } from "@circulusd/protocol-types";

export const WORKSPACE_STATE_SCHEMA_VERSION = 1 as const;
export const WORKSPACE_COMMAND_SCHEMA_VERSION = 1 as const;

export type WorkspaceBackend = "nsjail" | "docker" | "firecracker";
export type WorkspaceAccessMode = "read_only" | "read_write";
export type WorkspaceLeaseWaitPolicy = "queue" | "fail";
export type WorkspacePermission = "workspace.read" | "workspace.write";
export type WorkspaceAuthorityPurpose = "admission" | "settlement";

/**
 * A fresh, authoritative broker snapshot. Callers supply resource IDs only as
 * comparison targets; the broker adapter must populate this value from the
 * Session authority before invoking the aggregate.
 */
export interface WorkspaceAuthoritySnapshot {
  readonly purpose: WorkspaceAuthorityPurpose;
  readonly serviceBinding: "workspace";
  readonly tenantId: string;
  readonly userId: string;
  readonly sessionId: string;
  readonly workspaceId: string;
  readonly turnId: string;
  readonly runtimeRevision: string;
  readonly policySnapshotDigest: Digest;
  readonly emergencyOverlayDigest: Digest;
  readonly effectivePermissions: readonly WorkspacePermission[];
  readonly sessionStatus: "active" | "closed";
  readonly turnStatus: "active" | "settling" | "aborting" | "completed";
  readonly turnLeaseActive: boolean;
  readonly turnLeaseExpiresAt: number;
  readonly effectStatus: "prepared" | "dispatched" | "externally_committed";
  readonly effectId: string;
  readonly invocationId: string;
  readonly requestDigest: Digest;
  readonly replayPolicy: ReplayPolicy;
  readonly dispatchAttempt: number;
  readonly sandboxId: string;
  readonly backend: WorkspaceBackend;
  readonly turnLeaseGeneration: number;
  readonly placementGeneration: number;
  readonly sandboxGeneration: number;
  readonly authorizationGeneration: number;
  readonly issuedAt: number;
  readonly expiresAt: number;
}

/** A GC-layer proof produced only after tenant-scoped guard CAS succeeds. */
export interface WorkspaceProtectionProof {
  readonly permitId: string;
  readonly tenantId: string;
  readonly objectDigest: Digest;
  readonly guardGeneration: number;
  readonly status: "protected";
}

export interface CreateWorkspaceStateInput {
  readonly workspaceId: string;
  readonly tenantId: string;
  readonly initialRootDigest: Digest;
}

export interface WorkspaceRevision {
  readonly revision: number;
  readonly parentRevision: number | null;
  readonly rootDigest: Digest;
  readonly workspaceCommitId: string | null;
  readonly invocationId: string | null;
  readonly requestDigest: Digest | null;
  readonly referencedObjectDigests: readonly Digest[];
  readonly pendingProtectionPermitIds: readonly string[];
  readonly committedAt: number | null;
}

export interface WorkspaceLeaseRenewalReceipt {
  readonly renewalSequence: number;
  readonly requestedLeaseTtlMs: number;
  readonly expiresAt: number;
}

export interface WorkspaceWriteLease {
  readonly leaseId: string;
  readonly workspaceId: string;
  readonly tenantId: string;
  readonly userId: string;
  readonly invocationId: string;
  readonly requestDigest: Digest;
  readonly effectId: string;
  readonly sessionId: string;
  readonly turnId: string;
  readonly sandboxId: string;
  readonly backend: WorkspaceBackend;
  readonly baseRevision: number;
  readonly leaseGeneration: number;
  readonly dispatchAttempt: number;
  readonly turnLeaseGeneration: number;
  readonly placementGeneration: number;
  readonly sandboxGeneration: number;
  readonly projectionGeneration: number;
  readonly authorizationGeneration: number;
  readonly admissionAuthority: WorkspaceAuthoritySnapshot;
  readonly requestedLeaseTtlMs: number;
  readonly requestedMaximumHoldMs: number;
  readonly acquireDeadline: number;
  readonly waitPolicy: WorkspaceLeaseWaitPolicy;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly maximumHoldDeadline: number;
  readonly renewalSequence: number;
  readonly enqueueSequence: number;
  readonly lastRenewal: WorkspaceLeaseRenewalReceipt | null;
}

export interface WorkspaceLeaseQueueEntry {
  readonly authority: WorkspaceAuthoritySnapshot;
  readonly requestedLeaseId: string;
  readonly sandboxId: string;
  readonly backend: WorkspaceBackend;
  readonly projectionGeneration: number;
  readonly requestedLeaseTtlMs: number;
  readonly requestedMaximumHoldMs: number;
  readonly acquireDeadline: number;
  readonly waitPolicy: WorkspaceLeaseWaitPolicy;
  readonly enqueueSequence: number;
  readonly canceled: boolean;
}

export type WorkspaceLeaseHistoryStatus =
  | "queued"
  | "active"
  | "canceled"
  | "timed_out"
  | "expired"
  | "released"
  | "committed";

export interface WorkspaceLeaseHistoryRecord {
  readonly invocationId: string;
  readonly requestDigest: Digest;
  readonly latestProjectionGeneration: number;
  readonly latestDispatchAttempt: number;
  readonly latestLeaseGeneration: number | null;
  readonly latestEnqueueSequence: number;
  readonly status: WorkspaceLeaseHistoryStatus;
}

export interface WorkspaceWriteLeaseConflictOutcome {
  readonly kind: "write_lease_conflict";
  readonly holderSessionId: string;
  /** Zero means that the FIFO head has not yet acquired a concrete lease generation. */
  readonly leaseGeneration: number;
  readonly expiresAt: number;
}

/** Durable negative receipt for an invocation-bound fail-policy acquisition. */
export interface WorkspaceLeaseConflictRecord {
  readonly invocationId: string;
  readonly requestDigest: Digest;
  readonly dispatchAttempt: number;
  readonly authority: WorkspaceAuthoritySnapshot;
  readonly requestedLeaseId: string;
  readonly sandboxId: string;
  readonly backend: WorkspaceBackend;
  readonly projectionGeneration: number;
  readonly requestedLeaseTtlMs: number;
  readonly requestedMaximumHoldMs: number;
  readonly acquireDeadline: number;
  readonly waitPolicy: "fail";
  readonly recordedAt: number;
  readonly outcome: WorkspaceWriteLeaseConflictOutcome;
}

export interface WorkspaceLeaseFence {
  readonly leaseId: string;
  readonly invocationId: string;
  readonly requestDigest: Digest;
  readonly effectId: string;
  readonly sessionId: string;
  readonly sandboxId: string;
  readonly leaseGeneration: number;
  readonly dispatchAttempt: number;
  readonly turnLeaseGeneration: number;
  readonly placementGeneration: number;
  readonly sandboxGeneration: number;
  readonly projectionGeneration: number;
  readonly authorizationGeneration: number;
}

export interface WorkspaceMaterializationTicket {
  readonly ticketId: string;
  readonly accessMode: WorkspaceAccessMode;
  readonly workspaceId: string;
  readonly tenantId: string;
  readonly userId: string;
  readonly invocationId: string;
  readonly requestDigest: Digest;
  readonly effectId: string;
  readonly sessionId: string;
  readonly turnId: string;
  readonly sandboxId: string;
  readonly backend: WorkspaceBackend;
  readonly revision: number;
  readonly rootDigest: Digest;
  readonly leaseId: string | null;
  readonly leaseGeneration: number | null;
  readonly dispatchAttempt: number;
  readonly turnLeaseGeneration: number;
  readonly placementGeneration: number;
  readonly sandboxGeneration: number;
  readonly projectionGeneration: number;
  readonly authorizationGeneration: number;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly requestedTicketTtlMs: number;
  readonly admissionAuthority: WorkspaceAuthoritySnapshot;
}

export interface WorkspaceCommitResult {
  readonly workspaceCommitId: string;
  readonly revision: number;
  readonly rootDigest: Digest;
}

export interface WorkspaceInvocationRecord {
  readonly invocationId: string;
  readonly requestDigest: Digest;
  readonly baseRevision: number;
  readonly status: "committed";
  readonly result: WorkspaceCommitResult;
  readonly referencedObjectDigests: readonly Digest[];
  readonly pendingProtectionPermitIds: readonly string[];
  readonly protectionProofs: readonly WorkspaceProtectionProof[];
  readonly materializationTicketId: string;
  readonly leaseFence: WorkspaceLeaseFence;
  readonly commitAuthority: WorkspaceAuthoritySnapshot;
}

export interface WorkspaceAggregateState {
  schemaVersion: typeof WORKSPACE_STATE_SCHEMA_VERSION;
  workspaceId: string;
  tenantId: string;
  eventSequence: number;
  revision: number;
  rootDigest: Digest;
  revisions: WorkspaceRevision[];
  nextLeaseGeneration: number;
  nextLeaseEnqueueSequence: number;
  activeWriteLease: WorkspaceWriteLease | null;
  writeQueue: WorkspaceLeaseQueueEntry[];
  leaseHistory: WorkspaceLeaseHistoryRecord[];
  leaseConflicts: WorkspaceLeaseConflictRecord[];
  materializationTickets: WorkspaceMaterializationTicket[];
  knownLeaseIds: string[];
  knownMaterializationTicketIds: string[];
  invocationLedger: WorkspaceInvocationRecord[];
}

interface WorkspaceCommandBase {
  /** Durable-object transaction fence, not a tenant-selected sequence. */
  readonly expectedEventSequence: number;
  /** Server-observed transaction time injected by the trusted adapter. */
  readonly now: number;
}

export interface AcquireWriteLeaseCommand extends WorkspaceCommandBase {
  readonly kind: "acquire_write_lease";
  readonly authority: WorkspaceAuthoritySnapshot;
  readonly requestedLeaseId: string;
  readonly sandboxId: string;
  readonly backend: WorkspaceBackend;
  readonly projectionGeneration: number;
  readonly requestedLeaseTtlMs: number;
  readonly requestedMaximumHoldMs: number;
  readonly acquireDeadline: number;
  readonly waitPolicy: WorkspaceLeaseWaitPolicy;
}

export interface RenewWriteLeaseCommand extends WorkspaceCommandBase {
  readonly kind: "renew_write_lease";
  readonly leaseFence: WorkspaceLeaseFence;
  readonly nextRenewalSequence: number;
  readonly requestedLeaseTtlMs: number;
  readonly authority: WorkspaceAuthoritySnapshot;
}

export interface ReleaseWriteLeaseCommand extends WorkspaceCommandBase {
  readonly kind: "release_write_lease";
  readonly leaseFence: WorkspaceLeaseFence;
  readonly authority: WorkspaceAuthoritySnapshot;
}

export interface CancelWriteLeaseRequestCommand extends WorkspaceCommandBase {
  readonly kind: "cancel_write_lease_request";
  readonly invocationId: string;
  readonly requestDigest: Digest;
  readonly authority: WorkspaceAuthoritySnapshot;
}

export interface ReconcileWriteQueueCommand extends WorkspaceCommandBase {
  /** Internal alarm/recovery command; broker tenants must not invoke it directly. */
  readonly kind: "reconcile_write_queue";
}

export interface PrepareMaterializationCommand extends WorkspaceCommandBase {
  readonly kind: "prepare_materialization";
  readonly ticketId: string;
  readonly accessMode: WorkspaceAccessMode;
  readonly requestedRevision: number;
  readonly authority: WorkspaceAuthoritySnapshot;
  readonly sandboxId: string;
  readonly backend: WorkspaceBackend;
  readonly projectionGeneration: number;
  readonly leaseFence: WorkspaceLeaseFence | null;
  readonly ticketTtlMs: number;
}

export interface CommitWorkspaceCommand extends WorkspaceCommandBase {
  readonly kind: "commit_workspace";
  readonly materializationTicketId: string;
  readonly leaseFence: WorkspaceLeaseFence;
  readonly baseRevision: number;
  readonly workspaceCommitId: string;
  readonly postExecutionRootDigest: Digest;
  readonly referencedObjectDigests: readonly Digest[];
  readonly protectionProofs: readonly WorkspaceProtectionProof[];
  readonly authority: WorkspaceAuthoritySnapshot;
}

export type WorkspaceCommand =
  | AcquireWriteLeaseCommand
  | RenewWriteLeaseCommand
  | ReleaseWriteLeaseCommand
  | CancelWriteLeaseRequestCommand
  | ReconcileWriteQueueCommand
  | PrepareMaterializationCommand
  | CommitWorkspaceCommand;

export type WorkspaceCommandOutcome =
  | { readonly kind: "write_lease_acquired"; readonly lease: WorkspaceWriteLease }
  | {
      readonly kind: "write_lease_queued";
      readonly invocationId: string;
      readonly enqueueSequence: number;
      readonly queuePosition: number;
    }
  | WorkspaceWriteLeaseConflictOutcome
  | {
      readonly kind: "write_lease_renewed";
      readonly leaseId: string;
      readonly renewalSequence: number;
      readonly expiresAt: number;
    }
  | {
      readonly kind: "write_lease_released";
      readonly leaseId: string;
      readonly promotedInvocationId: string | null;
    }
  | {
      readonly kind: "write_lease_request_canceled";
      readonly invocationId: string;
      readonly enqueueSequence: number;
    }
  | {
      readonly kind: "write_queue_reconciled";
      readonly promotedInvocationId: string | null;
    }
  | {
      readonly kind: "materialization_prepared";
      readonly ticket: WorkspaceMaterializationTicket;
    }
  | { readonly kind: "workspace_committed"; readonly result: WorkspaceCommitResult };

export interface ApplyWorkspaceCommandResult {
  readonly state: WorkspaceAggregateState;
  readonly outcome: WorkspaceCommandOutcome;
  readonly commandDigest: Digest;
  readonly replayed: boolean;
}
