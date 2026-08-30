import type { Digest } from "@circulusd/protocol-types";
import { describe, expect, it } from "vitest";

import {
  applySessionCommand,
  type SessionAggregateState,
} from "../src/session/index.ts";
import {
  assertWorkspaceInvariants,
  createWorkspaceState,
  deriveSessionWorkspaceRecoveryFence,
  projectWorkspaceInvocationForRecovery,
  type SessionWorkspaceRecoveryFence,
  type WorkspaceAggregateState,
} from "../src/workspace/index.ts";
import { RecoverableWorkspaceEffect } from "./support/recoverable-workspace-effect.ts";

const INITIAL_ROOT = `sha256:${"0".repeat(64)}` as Digest;
const RUNTIME_REVISION = `sha256:${"1".repeat(64)}` as Digest;
const POLICY_SNAPSHOT = `sha256:${"2".repeat(64)}` as Digest;
const COMMITTED_ROOT = `sha256:${"4".repeat(64)}` as Digest;
const ROTATED_EMERGENCY_OVERLAY = `sha256:${"7".repeat(64)}` as Digest;

async function committedRecoverySnapshot(): Promise<{
  readonly session: SessionAggregateState;
  readonly workspace: WorkspaceAggregateState;
}> {
  return RecoverableWorkspaceEffect.createCrashed().then((fixture) => fixture.snapshot());
}

describe("Session-derived Workspace recovery projection", () => {
  it("derives the recovery fence from the sole active effect without caller identity", async () => {
    const { session } = await committedRecoverySnapshot();

    expect(deriveSessionWorkspaceRecoveryFence).toHaveLength(1);
    const fence = await deriveSessionWorkspaceRecoveryFence(session);
    expect(fence).toEqual({
      observedSessionEventSequence: 3,
      currentSessionFence: {
        turnLeaseGeneration: 10,
        placementGeneration: 4,
        sandboxGeneration: 5,
        authorizationGeneration: 6,
      },
      tenantId: "phase0b-tenant",
      userId: "phase0b-user",
      sessionId: "phase0b-session",
      workspaceId: "phase0b-workspace",
      turnId: "phase0b-turn",
      runtimeRevisionDigest: RUNTIME_REVISION,
      policySnapshotDigest: POLICY_SNAPSHOT,
      service: "workspace",
      operation: "workspace.commit",
      replayPolicy: "idempotency-key",
      effectId: "phase0b-workspace-effect",
      invocationId: "phase0b-workspace-invocation",
      requestDigest: session.effects[0]?.requestDigest,
      dispatchAttempt: 1,
      dispatchFence: {
        turnLeaseGeneration: 10,
        placementGeneration: 4,
        sandboxGeneration: 5,
        authorizationGeneration: 6,
      },
      providerRequestId: null,
    });

    const forgedCallerIdentity = {
      tenantId: "attacker-tenant",
      workspaceId: "attacker-workspace",
      effectId: "attacker-effect",
      invocationId: "attacker-invocation",
      operation: "workspace.delete",
    };
    const reflected = await Reflect.apply(
      deriveSessionWorkspaceRecoveryFence,
      undefined,
      [session, forgedCallerIdentity],
    );
    expect(reflected).toEqual(fence);
  });

  it("snapshots mutable Session authority before its first asynchronous validation yield", async () => {
    const { session } = await committedRecoverySnapshot();
    const activeTurn = session.activeTurn;
    const effect = session.effects[0];
    if (activeTurn === null || effect === undefined || effect.lastDispatch === null) {
      throw new Error("expected an active dispatched Workspace effect");
    }
    const sessionAtCall = structuredClone(session);

    const pendingFence = deriveSessionWorkspaceRecoveryFence(session);
    Reflect.set(session, "tenantId", "mutated-tenant");
    Reflect.set(session, "workspaceId", "mutated-workspace");
    Reflect.set(session, "placementGeneration", 40);
    Reflect.set(session, "sandboxGeneration", 50);
    Reflect.set(session, "authorizationGeneration", 60);
    Reflect.set(activeTurn, "turnLeaseGeneration", 100);
    Reflect.set(effect, "operation", "workspace.delete");
    Reflect.set(effect.lastDispatch, "turnLeaseGeneration", 101);
    Reflect.set(effect.lastDispatch, "placementGeneration", 41);
    Reflect.set(effect.lastDispatch, "sandboxGeneration", 51);
    Reflect.set(effect.lastDispatch, "authorizationGeneration", 61);
    Reflect.set(effect.lastDispatch, "providerRequestId", "mutated-provider-request");

    const fence = await pendingFence;
    const expectedFence = await deriveSessionWorkspaceRecoveryFence(sessionAtCall);
    expect(fence).toEqual(expectedFence);
    expect(fence).toMatchObject({
      tenantId: "phase0b-tenant",
      workspaceId: "phase0b-workspace",
      operation: "workspace.commit",
      currentSessionFence: {
        turnLeaseGeneration: 10,
        placementGeneration: 4,
        sandboxGeneration: 5,
        authorizationGeneration: 6,
      },
      dispatchFence: {
        turnLeaseGeneration: 10,
        placementGeneration: 4,
        sandboxGeneration: 5,
        authorizationGeneration: 6,
      },
      providerRequestId: null,
    });
  });

  it("projects only the exact revision-backed committed Workspace result", async () => {
    const { session, workspace } = await committedRecoverySnapshot();
    const fence = await deriveSessionWorkspaceRecoveryFence(session);
    if (fence === null) {
      throw new Error("expected a dispatched Workspace recovery fence");
    }

    expect(projectWorkspaceInvocationForRecovery).toHaveLength(2);
    expect(projectWorkspaceInvocationForRecovery(workspace, fence)).toEqual({
      status: "committed",
      fence,
      result: {
        workspaceCommitId: "phase0b-workspace-commit",
        revision: 1,
        rootDigest: COMMITTED_ROOT,
      },
    });
  });

  it("projects absence without fabricating a commit or result", async () => {
    const { session } = await committedRecoverySnapshot();
    const fence = await deriveSessionWorkspaceRecoveryFence(session);
    if (fence === null) {
      throw new Error("expected a dispatched Workspace recovery fence");
    }
    const emptyWorkspace = createWorkspaceState({
      tenantId: session.tenantId,
      workspaceId: session.workspaceId,
      initialRootDigest: INITIAL_ROOT,
    });

    expect(projectWorkspaceInvocationForRecovery(emptyWorkspace, fence)).toEqual({
      status: "absent",
      fence,
      result: null,
    });
  });

  it("accepts only dispatch <= commit <= current non-widening authorization rotation", async () => {
    const { session, workspace } = await committedRecoverySnapshot();
    const rotatedSession = await applySessionCommand(session, {
      kind: "rotate_generations",
      commandId: "rotate-workspace-recovery-authorization",
      expectedEventSequence: session.eventSequence,
      nextPlacementGeneration: session.placementGeneration,
      nextSandboxGeneration: session.sandboxGeneration,
      nextAuthorizationGeneration: 7,
      nextEmergencyOverlayDigest: ROTATED_EMERGENCY_OVERLAY,
    });
    const fence = await deriveSessionWorkspaceRecoveryFence(rotatedSession.state);
    if (fence === null) {
      throw new Error("expected a dispatched Workspace recovery fence");
    }
    expect(fence).toMatchObject({
      currentSessionFence: { authorizationGeneration: 7 },
      dispatchFence: { authorizationGeneration: 6 },
    });

    const rotatedWorkspace = structuredClone(workspace);
    const rotatedRecord = rotatedWorkspace.invocationLedger[0];
    if (rotatedRecord === undefined) {
      throw new Error("expected a committed Workspace invocation");
    }
    Reflect.set(rotatedRecord.commitAuthority, "authorizationGeneration", 7);
    Reflect.set(
      rotatedRecord.commitAuthority,
      "emergencyOverlayDigest",
      ROTATED_EMERGENCY_OVERLAY,
    );
    Reflect.set(rotatedRecord.commitAuthority, "effectivePermissions", ["workspace.read"]);
    expect(() => assertWorkspaceInvariants(rotatedWorkspace)).not.toThrow();
    expect(projectWorkspaceInvocationForRecovery(rotatedWorkspace, fence)).toMatchObject({
      status: "committed",
      result: { workspaceCommitId: "phase0b-workspace-commit", revision: 1 },
    });

    const commitBeforeDispatch = structuredClone(rotatedWorkspace);
    const earlyRecord = commitBeforeDispatch.invocationLedger[0];
    if (earlyRecord === undefined) {
      throw new Error("expected a committed Workspace invocation");
    }
    Reflect.set(earlyRecord.commitAuthority, "authorizationGeneration", 5);
    expect(() =>
      projectWorkspaceInvocationForRecovery(commitBeforeDispatch, fence),
    ).toThrow();

    const commitAfterCurrent = structuredClone(rotatedWorkspace);
    const lateRecord = commitAfterCurrent.invocationLedger[0];
    if (lateRecord === undefined) {
      throw new Error("expected a committed Workspace invocation");
    }
    Reflect.set(lateRecord.commitAuthority, "authorizationGeneration", 8);
    expect(() =>
      projectWorkspaceInvocationForRecovery(commitAfterCurrent, fence),
    ).toThrow();
  });

  it("fails closed on malformed or unprovable Workspace ledger identity", async () => {
    const { session, workspace } = await committedRecoverySnapshot();
    const fence = await deriveSessionWorkspaceRecoveryFence(session);
    if (fence === null) {
      throw new Error("expected a dispatched Workspace recovery fence");
    }

    const corruptRevision = structuredClone(workspace);
    const corruptRevisionRecord = corruptRevision.invocationLedger[0];
    if (corruptRevisionRecord === undefined) {
      throw new Error("expected a committed Workspace invocation");
    }
    Reflect.set(corruptRevisionRecord.result, "revision", 2);
    const corruptRevisionBefore = structuredClone(corruptRevision);
    expect(() => projectWorkspaceInvocationForRecovery(corruptRevision, fence)).toThrow();
    expect(corruptRevision).toEqual(corruptRevisionBefore);

    const corruptOperation = structuredClone(workspace);
    const corruptOperationRecord = corruptOperation.invocationLedger[0];
    if (corruptOperationRecord === undefined) {
      throw new Error("expected a committed Workspace invocation");
    }
    Reflect.set(corruptOperationRecord.commitAuthority, "effectOperation", "workspace.delete");
    const corruptOperationBefore = structuredClone(corruptOperation);
    expect(() => projectWorkspaceInvocationForRecovery(corruptOperation, fence)).toThrow();
    expect(corruptOperation).toEqual(corruptOperationBefore);

    const corruptDispatchFence = structuredClone(workspace);
    const corruptDispatchRecord = corruptDispatchFence.invocationLedger[0];
    if (corruptDispatchRecord === undefined) {
      throw new Error("expected a committed Workspace invocation");
    }
    Reflect.set(
      corruptDispatchRecord.leaseFence,
      "placementGeneration",
      corruptDispatchRecord.leaseFence.placementGeneration + 1,
    );
    const corruptDispatchBefore = structuredClone(corruptDispatchFence);
    expect(() =>
      projectWorkspaceInvocationForRecovery(corruptDispatchFence, fence),
    ).toThrow();
    expect(corruptDispatchFence).toEqual(corruptDispatchBefore);

    const providerRelabeled: SessionWorkspaceRecoveryFence = {
      ...fence,
      providerRequestId: "unproven-provider-request",
    };
    expect(() =>
      projectWorkspaceInvocationForRecovery(workspace, providerRelabeled),
    ).toThrow();
  });

  it("isolates 64 concurrent exact and authority-or-dispatch-fence-relabeled lookups", async () => {
    const { session, workspace } = await committedRecoverySnapshot();
    const sessionBefore = structuredClone(session);
    const workspaceBefore = structuredClone(workspace);
    const fence = await deriveSessionWorkspaceRecoveryFence(session);
    if (fence === null) {
      throw new Error("expected a dispatched Workspace recovery fence");
    }

    const lookups = Array.from({ length: 64 }, async (_, index) => {
      if (index < 32) {
        return projectWorkspaceInvocationForRecovery(workspace, fence);
      }
      const relabeled: SessionWorkspaceRecoveryFence = index % 2 === 0
        ? { ...fence, operation: "workspace.delete" }
        : {
            ...fence,
            dispatchFence: {
              ...fence.dispatchFence,
              placementGeneration: fence.dispatchFence.placementGeneration + 1,
            },
          };
      return projectWorkspaceInvocationForRecovery(workspace, relabeled);
    });
    const results = await Promise.allSettled(lookups);

    expect(results).toHaveLength(64);
    for (const [index, result] of results.entries()) {
      if (index < 32) {
        expect(result.status).toBe("fulfilled");
        if (result.status === "fulfilled") {
          expect(result.value).toMatchObject({
            status: "committed",
            result: { workspaceCommitId: "phase0b-workspace-commit", revision: 1 },
          });
        }
      } else {
        expect(result.status).toBe("rejected");
        if (result.status === "rejected") {
          expect(result.reason).toMatchObject({ code: "STALE_GENERATION" });
        }
      }
    }
    expect(session).toEqual(sessionBefore);
    expect(workspace).toEqual(workspaceBefore);
  });
});
