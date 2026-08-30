import {
  parseDigest,
  type Digest,
  type ReplayPolicy,
} from "@circulusd/protocol-types";

import {
  validateSessionState,
  type SessionAggregateState,
  type SessionFence,
} from "../session/index.ts";
import { assertWorkspaceInvariants } from "./aggregate.ts";
import { workspaceError } from "./errors.ts";
import type {
  WorkspaceAggregateState,
  WorkspaceCommitResult,
} from "./types.ts";

/**
 * Query-only authority derived from one authoritative Session snapshot.
 *
 * The current fence is reserved for the Session CAS that consumes a recovery
 * result. The dispatch fence is historical proof used to exact-match the
 * Workspace commit. Neither fence authorizes a replay by itself.
 */
export interface SessionWorkspaceRecoveryFence {
  readonly observedSessionEventSequence: number;
  readonly currentSessionFence: SessionFence;
  readonly tenantId: string;
  readonly userId: string;
  readonly sessionId: string;
  readonly workspaceId: string;
  readonly turnId: string;
  readonly runtimeRevisionDigest: Digest;
  readonly policySnapshotDigest: Digest;
  readonly service: "workspace";
  readonly operation: string;
  readonly replayPolicy: ReplayPolicy;
  readonly effectId: string;
  readonly invocationId: string;
  readonly requestDigest: Digest;
  readonly dispatchAttempt: number;
  readonly dispatchFence: SessionFence;
  readonly providerRequestId: string | null;
}

export type WorkspaceInvocationRecoveryProjection =
  | {
      readonly status: "committed";
      readonly fence: SessionWorkspaceRecoveryFence;
      readonly result: WorkspaceCommitResult;
    }
  | {
      /** Advisory only: absence is not proof that replay is safe. */
      readonly status: "absent";
      readonly fence: SessionWorkspaceRecoveryFence;
      readonly result: null;
    };

/**
 * Derives a Workspace recovery query from Session authority only. There are no
 * caller-selected route or effect identity parameters.
 */
export async function deriveSessionWorkspaceRecoveryFence(
  state: SessionAggregateState,
): Promise<SessionWorkspaceRecoveryFence | null> {
  const snapshot = structuredClone(state);
  await validateSessionState(snapshot);
  const activeTurn = snapshot.activeTurn;
  if (activeTurn === null || activeTurn.activeEffectId === null) {
    return null;
  }
  const effect = snapshot.effects.find(
    (candidate) => candidate.effectId === activeTurn.activeEffectId,
  );
  if (effect === undefined) {
    workspaceError(
      "FAILED_PRECONDITION",
      "the active Session effect is missing from durable state",
    );
  }
  if (effect.service !== "workspace" || effect.phase !== "dispatched") {
    return null;
  }
  if (effect.lastDispatch === null) {
    workspaceError(
      "FAILED_PRECONDITION",
      "the dispatched Workspace effect lacks a dispatch fence",
    );
  }

  return {
    observedSessionEventSequence: snapshot.eventSequence,
    currentSessionFence: {
      turnLeaseGeneration: activeTurn.turnLeaseGeneration,
      placementGeneration: snapshot.placementGeneration,
      sandboxGeneration: snapshot.sandboxGeneration,
      authorizationGeneration: snapshot.authorizationGeneration,
    },
    tenantId: snapshot.tenantId,
    userId: snapshot.userId,
    sessionId: snapshot.sessionId,
    workspaceId: snapshot.workspaceId,
    turnId: activeTurn.turnId,
    runtimeRevisionDigest: snapshot.runtimeRevisionDigest,
    policySnapshotDigest: snapshot.policySnapshotDigest,
    service: "workspace",
    operation: effect.operation,
    replayPolicy: effect.replayPolicy,
    effectId: effect.effectId,
    invocationId: effect.invocationId,
    requestDigest: effect.requestDigest,
    dispatchAttempt: effect.dispatchAttempt,
    dispatchFence: {
      turnLeaseGeneration: effect.lastDispatch.turnLeaseGeneration,
      placementGeneration: effect.lastDispatch.placementGeneration,
      sandboxGeneration: effect.lastDispatch.sandboxGeneration,
      authorizationGeneration: effect.lastDispatch.authorizationGeneration,
    },
    providerRequestId: effect.lastDispatch.providerRequestId,
  };
}

/**
 * Projects a Workspace invocation ledger result without mutating either
 * aggregate. A committed result still requires an exact current-fence CAS in
 * Session before it can advance the effect.
 */
export function projectWorkspaceInvocationForRecovery(
  state: WorkspaceAggregateState,
  fence: SessionWorkspaceRecoveryFence,
): WorkspaceInvocationRecoveryProjection {
  assertWorkspaceInvariants(state);
  parseDigest(fence.runtimeRevisionDigest, "recovery fence runtimeRevisionDigest");
  parseDigest(fence.policySnapshotDigest, "recovery fence policySnapshotDigest");
  parseDigest(fence.requestDigest, "recovery fence requestDigest");

  if (
    fence.service !== "workspace" ||
    fence.providerRequestId !== null ||
    state.tenantId !== fence.tenantId ||
    state.workspaceId !== fence.workspaceId ||
    fence.userId.length === 0 ||
    fence.sessionId.length === 0 ||
    fence.turnId.length === 0 ||
    fence.operation.length === 0 ||
    fence.effectId.length === 0 ||
    fence.invocationId.length === 0 ||
    !Number.isSafeInteger(fence.observedSessionEventSequence) ||
    fence.observedSessionEventSequence < 1 ||
    !Number.isSafeInteger(fence.dispatchAttempt) ||
    fence.dispatchAttempt < 1 ||
    !Number.isSafeInteger(fence.currentSessionFence.turnLeaseGeneration) ||
    fence.currentSessionFence.turnLeaseGeneration < 0 ||
    !Number.isSafeInteger(fence.currentSessionFence.placementGeneration) ||
    fence.currentSessionFence.placementGeneration < 0 ||
    !Number.isSafeInteger(fence.currentSessionFence.sandboxGeneration) ||
    fence.currentSessionFence.sandboxGeneration < 0 ||
    !Number.isSafeInteger(fence.currentSessionFence.authorizationGeneration) ||
    fence.currentSessionFence.authorizationGeneration < 0 ||
    !Number.isSafeInteger(fence.dispatchFence.turnLeaseGeneration) ||
    fence.dispatchFence.turnLeaseGeneration < 0 ||
    !Number.isSafeInteger(fence.dispatchFence.placementGeneration) ||
    fence.dispatchFence.placementGeneration < 0 ||
    !Number.isSafeInteger(fence.dispatchFence.sandboxGeneration) ||
    fence.dispatchFence.sandboxGeneration < 0 ||
    !Number.isSafeInteger(fence.dispatchFence.authorizationGeneration) ||
    fence.dispatchFence.authorizationGeneration < 0
  ) {
    workspaceError(
      "STALE_GENERATION",
      "the Session-derived Workspace recovery fence is not provable",
    );
  }

  const record = state.invocationLedger.find(
    (candidate) => candidate.invocationId === fence.invocationId,
  );
  if (record === undefined) {
    return {
      status: "absent",
      fence: structuredClone(fence),
      result: null,
    };
  }
  if (record.requestDigest !== fence.requestDigest) {
    workspaceError(
      "IDEMPOTENCY_CONFLICT",
      "the Workspace invocation changed request digest",
    );
  }

  const authority = record.commitAuthority;
  const lease = record.leaseFence;
  if (
    authority.purpose !== "settlement" ||
    authority.serviceBinding !== "workspace" ||
    authority.tenantId !== fence.tenantId ||
    authority.userId !== fence.userId ||
    authority.sessionId !== fence.sessionId ||
    authority.workspaceId !== fence.workspaceId ||
    authority.turnId !== fence.turnId ||
    authority.runtimeRevision !== fence.runtimeRevisionDigest ||
    authority.policySnapshotDigest !== fence.policySnapshotDigest ||
    authority.effectStatus !== "dispatched" ||
    authority.effectService !== fence.service ||
    authority.effectOperation !== fence.operation ||
    authority.effectId !== fence.effectId ||
    authority.invocationId !== fence.invocationId ||
    authority.requestDigest !== fence.requestDigest ||
    authority.replayPolicy !== fence.replayPolicy ||
    authority.dispatchAttempt !== fence.dispatchAttempt ||
    authority.turnLeaseGeneration !== fence.dispatchFence.turnLeaseGeneration ||
    authority.placementGeneration !== fence.dispatchFence.placementGeneration ||
    authority.sandboxGeneration !== fence.dispatchFence.sandboxGeneration ||
    authority.authorizationGeneration <
      fence.dispatchFence.authorizationGeneration ||
    authority.authorizationGeneration >
      fence.currentSessionFence.authorizationGeneration ||
    lease.invocationId !== fence.invocationId ||
    lease.requestDigest !== fence.requestDigest ||
    lease.effectId !== fence.effectId ||
    lease.sessionId !== fence.sessionId ||
    lease.dispatchAttempt !== fence.dispatchAttempt ||
    lease.turnLeaseGeneration !== fence.dispatchFence.turnLeaseGeneration ||
    lease.placementGeneration !== fence.dispatchFence.placementGeneration ||
    lease.sandboxGeneration !== fence.dispatchFence.sandboxGeneration ||
    lease.authorizationGeneration !== fence.dispatchFence.authorizationGeneration
  ) {
    workspaceError(
      "STALE_GENERATION",
      "the Workspace commit does not match the Session dispatch fence",
    );
  }

  return {
    status: "committed",
    fence: structuredClone(fence),
    result: structuredClone(record.result),
  };
}
