import { digestBytes, type Digest } from "@circulusd/protocol-types";

import type { AggregateAdapter } from "../../src/host/contracts.ts";
import { TransactionalAggregateKernel } from "../../src/host/kernel.ts";
import {
  applySessionCommand,
  checkpointDigest,
  createSessionState,
  effectRequestDigest,
  migrateSessionState,
  turnInputDigest,
  validateSessionState,
  type CreateSessionStateInput,
  type SessionAggregateState,
  type SessionCommand,
  type SessionCommandOutcome,
  type SessionFence,
} from "../../src/session/index.ts";
import {
  applyWorkspaceCommand,
  assertWorkspaceInvariants,
  createWorkspaceState,
  lookupWorkspaceInvocation,
  type CreateWorkspaceStateInput,
  type WorkspaceAggregateState,
  type WorkspaceAuthoritySnapshot,
  type WorkspaceCommand,
  type WorkspaceCommandOutcome,
  type WorkspaceLeaseFence,
} from "../../src/workspace/index.ts";
import {
  InjectedDurableStorageCrash,
  RestartableDurableStorage,
} from "./restartable-durable-storage.ts";

const RUNTIME_REVISION = `sha256:${"1".repeat(64)}` as Digest;
const POLICY_SNAPSHOT = `sha256:${"2".repeat(64)}` as Digest;
const EMERGENCY_OVERLAY = `sha256:${"3".repeat(64)}` as Digest;
const INITIAL_ROOT = `sha256:${"0".repeat(64)}` as Digest;
const COMMITTED_ROOT = `sha256:${"4".repeat(64)}` as Digest;
const PUBLIC_IDEMPOTENCY_KEY = `sha256:${"5".repeat(64)}` as Digest;
const PUBLIC_REQUEST = `sha256:${"6".repeat(64)}` as Digest;
const PROVIDER_ROUTE = `sha256:${"7".repeat(64)}` as Digest;

const sessionAdapter: AggregateAdapter<
  SessionAggregateState,
  CreateSessionStateInput,
  SessionCommand,
  SessionCommandOutcome
> = {
  kind: "phase0b-cross-do-session-reference",
  create: createSessionState,
  migrate: migrateSessionState,
  validate: validateSessionState,
  apply: applySessionCommand,
  version: (state) => state.eventSequence,
};

const workspaceAdapter: AggregateAdapter<
  WorkspaceAggregateState,
  CreateWorkspaceStateInput,
  WorkspaceCommand,
  WorkspaceCommandOutcome
> = {
  kind: "phase0b-cross-do-workspace-reference",
  create: createWorkspaceState,
  validate: assertWorkspaceInvariants,
  apply: applyWorkspaceCommand,
  version: (state) => state.eventSequence,
};

export const RECOVERABLE_WORKSPACE_EFFECT_EVIDENCE = Object.freeze({
  kind: "recoverable-workspace-effect-reference",
  referenceOnly: true,
  productionEligible: false,
  conformanceClaimed: false,
} as const);

export interface RecoverWorkspaceEffectOptions {
  readonly requestDigest?: Digest;
  readonly authorityOverrides?: Partial<WorkspaceAuthoritySnapshot>;
}

export interface RecoverWorkspaceEffectResult {
  readonly workspaceResult: {
    readonly workspaceCommitId: string;
    readonly revision: number;
    readonly rootDigest: Digest;
  };
  readonly externalCommit: {
    readonly replayed: boolean;
    readonly version: number;
  };
  readonly settlement: {
    readonly replayed: boolean;
    readonly version: number;
  };
}

interface RecoveryContext {
  readonly effectId: string;
  readonly invocationId: string;
  readonly requestDigest: Digest;
  readonly dispatchAttempt: number;
  readonly turnId: string;
  readonly fence: SessionFence;
  readonly settlementAuthority: WorkspaceAuthoritySnapshot;
  readonly resultRef: string;
}

interface RecoveryDiagnostics {
  workspaceAcquireExecutions: number;
  workspacePrepareExecutions: number;
  workspaceCommitExecutions: number;
  workspaceLedgerQueries: number;
}

/**
 * A deterministic cross-object recovery model for Phase 0B tests only.
 *
 * Each restart constructs fresh aggregate kernels over shared durable backings.
 * Recovery reads the committed Workspace invocation ledger and never sends a
 * mutating Workspace command. This does not emulate or qualify the production
 * Cloudflare Durable Objects runtime.
 */
export class RecoverableWorkspaceEffect {
  readonly evidence = RECOVERABLE_WORKSPACE_EFFECT_EVIDENCE;
  readonly #sessionStorage: RestartableDurableStorage;
  readonly #workspaceStorage: RestartableDurableStorage;
  readonly #sessionKernel: TransactionalAggregateKernel<
    SessionAggregateState,
    CreateSessionStateInput,
    SessionCommand,
    SessionCommandOutcome
  >;
  readonly #workspaceKernel: TransactionalAggregateKernel<
    WorkspaceAggregateState,
    CreateWorkspaceStateInput,
    WorkspaceCommand,
    WorkspaceCommandOutcome
  >;
  readonly #context: RecoveryContext;
  readonly #diagnostics: RecoveryDiagnostics;

  private constructor(
    sessionStorage: RestartableDurableStorage,
    workspaceStorage: RestartableDurableStorage,
    context: RecoveryContext,
    diagnostics: RecoveryDiagnostics,
  ) {
    this.#sessionStorage = sessionStorage;
    this.#workspaceStorage = workspaceStorage;
    this.#sessionKernel = new TransactionalAggregateKernel(
      { storage: sessionStorage },
      sessionAdapter,
    );
    this.#workspaceKernel = new TransactionalAggregateKernel(
      { storage: workspaceStorage },
      workspaceAdapter,
    );
    this.#context = structuredClone(context);
    this.#diagnostics = diagnostics;
  }

  static async createCrashed(): Promise<RecoverableWorkspaceEffect> {
    const sessionStorage = new RestartableDurableStorage();
    const workspaceStorage = new RestartableDurableStorage();
    const sessionKernel = new TransactionalAggregateKernel(
      { storage: sessionStorage },
      sessionAdapter,
    );
    const workspaceKernel = new TransactionalAggregateKernel(
      { storage: workspaceStorage },
      workspaceAdapter,
    );
    const diagnostics: RecoveryDiagnostics = {
      workspaceAcquireExecutions: 0,
      workspacePrepareExecutions: 0,
      workspaceCommitExecutions: 0,
      workspaceLedgerQueries: 0,
    };

    await Promise.all([
      sessionKernel.initialize({
        sessionId: "phase0b-session",
        tenantId: "phase0b-tenant",
        userId: "phase0b-user",
        workspaceId: "phase0b-workspace",
        runtimeRevisionDigest: RUNTIME_REVISION,
        policySnapshotDigest: POLICY_SNAPSHOT,
        emergencyOverlayDigest: EMERGENCY_OVERLAY,
        engineKind: "low-level",
        adapterAbiVersion: 1,
        checkpointSchemaVersion: 1,
        placementGeneration: 4,
        sandboxGeneration: 5,
        authorizationGeneration: 6,
      }),
      workspaceKernel.initialize({
        workspaceId: "phase0b-workspace",
        tenantId: "phase0b-tenant",
        initialRootDigest: INITIAL_ROOT,
      }),
    ]);

    const turnInput = { message: "commit one workspace revision" };
    const genesisPayload = new TextEncoder().encode("phase0b-genesis");
    await sessionKernel.execute({
      kind: "enqueue_turn",
      commandId: "phase0b-enqueue",
      expectedEventSequence: 0,
      transactionTime: 1_000,
      turnId: "phase0b-turn",
      input: turnInput,
      inputDigest: await turnInputDigest(turnInput),
      genesisCheckpoint: {
        kind: "genesis",
        engineKind: "low-level",
        adapterAbiVersion: 1,
        checkpointSchemaVersion: 1,
        runtimeRevisionDigest: RUNTIME_REVISION,
        sessionId: "phase0b-session",
        turnId: "phase0b-turn",
        checkpointSequence: 0,
        predecessorDigest: null,
        payloadEncoding: "opaque-v1",
        payloadBytes: genesisPayload,
        payloadDigest: await digestBytes(genesisPayload),
      },
      turnLeaseGeneration: 10,
      leaseExpiresAt: 100_000,
      publicAdmission: {
        authorizationGeneration: 6,
        idempotencyKeyDigest: PUBLIC_IDEMPOTENCY_KEY,
        requestDigest: PUBLIC_REQUEST,
      },
    });

    const admitted = await sessionKernel.query(null, (state) => state);
    if (admitted.activeTurn === null) {
      throw new Error("Phase 0B fixture requires an admitted active turn");
    }
    const effectRequest = {
      service: "workspace" as const,
      operation: "workspace.commit",
      replayPolicy: "idempotency-key" as const,
      payload: {
        workspaceId: "phase0b-workspace",
        postExecutionRootDigest: COMMITTED_ROOT,
      },
    };
    const enginePayload = new TextEncoder().encode("phase0b-effect-request");
    await sessionKernel.execute({
      kind: "commit_engine_step",
      commandId: "phase0b-prepare-workspace-effect",
      expectedEventSequence: 1,
      turnId: "phase0b-turn",
      fence: {
        turnLeaseGeneration: admitted.activeTurn.turnLeaseGeneration,
        placementGeneration: admitted.placementGeneration,
        sandboxGeneration: admitted.sandboxGeneration,
        authorizationGeneration: admitted.authorizationGeneration,
      },
      transactionTime: 1_100,
      consumedSettlementEffectId: null,
      effectIdentity: {
        effectId: "phase0b-workspace-effect",
        invocationId: "phase0b-workspace-invocation",
      },
      step: {
        kind: "effect_request",
        checkpoint: {
          kind: "engine",
          engineKind: admitted.engineKind,
          adapterAbiVersion: admitted.adapterAbiVersion,
          checkpointSchemaVersion: admitted.checkpointSchemaVersion,
          runtimeRevisionDigest: admitted.runtimeRevisionDigest,
          sessionId: admitted.sessionId,
          turnId: admitted.activeTurn.turnId,
          checkpointSequence: 1,
          predecessorDigest: await checkpointDigest(admitted.activeTurn.checkpoint),
          payloadEncoding: "opaque-v1",
          payloadBytes: enginePayload,
          payloadDigest: await digestBytes(enginePayload),
        },
        request: {
          ...effectRequest,
          requestDigest: await effectRequestDigest(effectRequest),
        },
      },
    });

    const prepared = await sessionKernel.query(null, (state) => state);
    const preparedEffect = prepared.effects[0];
    if (prepared.activeTurn === null || preparedEffect === undefined) {
      throw new Error("Phase 0B fixture requires a prepared workspace effect");
    }
    const fence: SessionFence = {
      turnLeaseGeneration: prepared.activeTurn.turnLeaseGeneration,
      placementGeneration: prepared.placementGeneration,
      sandboxGeneration: prepared.sandboxGeneration,
      authorizationGeneration: prepared.authorizationGeneration,
    };
    await sessionKernel.execute({
      kind: "dispatch_effect",
      commandId: "phase0b-dispatch-workspace-effect",
      expectedEventSequence: 2,
      turnId: prepared.activeTurn.turnId,
      effectId: preparedEffect.effectId,
      invocationId: preparedEffect.invocationId,
      requestDigest: preparedEffect.requestDigest,
      fence,
      transactionTime: 1_200,
      deadline: 9_000,
      providerRouteDigest: PROVIDER_ROUTE,
    });

    const dispatched = await sessionKernel.query(null, (state) => state);
    const dispatchedEffect = dispatched.effects[0];
    if (
      dispatched.activeTurn === null ||
      dispatchedEffect === undefined ||
      dispatchedEffect.lastDispatch === null
    ) {
      throw new Error("Phase 0B fixture requires a dispatched workspace effect");
    }
    if (dispatchedEffect.service !== "workspace") {
      throw new Error("Phase 0B fixture cannot mint Workspace authority for another service");
    }
    const admissionAuthority: WorkspaceAuthoritySnapshot = {
      purpose: "admission",
      serviceBinding: "workspace",
      tenantId: dispatched.tenantId,
      userId: dispatched.userId,
      sessionId: dispatched.sessionId,
      workspaceId: dispatched.workspaceId,
      turnId: dispatched.activeTurn.turnId,
      runtimeRevision: dispatched.runtimeRevisionDigest,
      policySnapshotDigest: dispatched.policySnapshotDigest,
      emergencyOverlayDigest: dispatched.emergencyOverlayDigest,
      effectivePermissions: ["workspace.read", "workspace.write"],
      sessionStatus: "active",
      turnStatus: "active",
      turnLeaseActive: true,
      turnLeaseExpiresAt: dispatched.activeTurn.leaseExpiresAt,
      effectStatus: "dispatched",
      effectService: dispatchedEffect.service,
      effectOperation: dispatchedEffect.operation,
      effectId: dispatchedEffect.effectId,
      invocationId: dispatchedEffect.invocationId,
      requestDigest: dispatchedEffect.requestDigest,
      replayPolicy: dispatchedEffect.replayPolicy,
      dispatchAttempt: dispatchedEffect.dispatchAttempt,
      sandboxId: "phase0b-sandbox",
      backend: "nsjail",
      turnLeaseGeneration: dispatchedEffect.lastDispatch.turnLeaseGeneration,
      placementGeneration: dispatchedEffect.lastDispatch.placementGeneration,
      sandboxGeneration: dispatchedEffect.lastDispatch.sandboxGeneration,
      authorizationGeneration: dispatchedEffect.lastDispatch.authorizationGeneration,
      issuedAt: 1_200,
      expiresAt: 10_000,
    };

    const acquired = await workspaceKernel.execute({
      kind: "acquire_write_lease",
      expectedEventSequence: 0,
      now: 2_000,
      authority: admissionAuthority,
      requestedLeaseId: "phase0b-workspace-lease",
      sandboxId: "phase0b-sandbox",
      backend: "nsjail",
      projectionGeneration: 7,
      requestedLeaseTtlMs: 5_000,
      requestedMaximumHoldMs: 8_000,
      acquireDeadline: 9_000,
      waitPolicy: "queue",
    });
    diagnostics.workspaceAcquireExecutions += 1;
    if (acquired.outcome.kind !== "write_lease_acquired") {
      throw new Error("Phase 0B fixture requires an acquired workspace lease");
    }
    const lease = acquired.outcome.lease;
    const leaseFence: WorkspaceLeaseFence = {
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
    await workspaceKernel.execute({
      kind: "prepare_materialization",
      expectedEventSequence: 1,
      now: 2_500,
      ticketId: "phase0b-workspace-ticket",
      accessMode: "read_write",
      requestedRevision: 0,
      authority: admissionAuthority,
      sandboxId: "phase0b-sandbox",
      backend: "nsjail",
      projectionGeneration: 7,
      leaseFence,
      ticketTtlMs: 4_000,
    });
    diagnostics.workspacePrepareExecutions += 1;
    const settlementAuthority: WorkspaceAuthoritySnapshot = {
      ...admissionAuthority,
      purpose: "settlement",
    };
    await workspaceKernel.execute({
      kind: "commit_workspace",
      expectedEventSequence: 2,
      now: 3_000,
      materializationTicketId: "phase0b-workspace-ticket",
      leaseFence,
      baseRevision: 0,
      workspaceCommitId: "phase0b-workspace-commit",
      postExecutionRootDigest: COMMITTED_ROOT,
      referencedObjectDigests: [COMMITTED_ROOT],
      protectionProofs: [
        {
          permitId: "phase0b-protection-permit",
          tenantId: "phase0b-tenant",
          objectDigest: COMMITTED_ROOT,
          guardGeneration: 1,
          status: "protected",
        },
      ],
      authority: settlementAuthority,
    });
    diagnostics.workspaceCommitExecutions += 1;

    sessionStorage.injectCrashOnce("before-commit");
    let injectedCrash: unknown;
    try {
      await sessionKernel.execute({
        kind: "record_external_commit",
        commandId: "phase0b-record-workspace-commit",
        expectedEventSequence: 3,
        turnId: dispatched.activeTurn.turnId,
        effectId: dispatchedEffect.effectId,
        invocationId: dispatchedEffect.invocationId,
        requestDigest: dispatchedEffect.requestDigest,
        dispatchAttempt: dispatchedEffect.dispatchAttempt,
        fence,
        externalCommitId: "phase0b-workspace-commit",
        resultRef: "phase0b-workspace-result-1",
      });
    } catch (error) {
      injectedCrash = error;
    }
    if (!(injectedCrash instanceof InjectedDurableStorageCrash)) {
      throw injectedCrash ?? new Error("Phase 0B fixture did not crash before Session commit");
    }

    return new RecoverableWorkspaceEffect(
      sessionStorage.restart(),
      workspaceStorage.restart(),
      {
        effectId: dispatchedEffect.effectId,
        invocationId: dispatchedEffect.invocationId,
        requestDigest: dispatchedEffect.requestDigest,
        dispatchAttempt: dispatchedEffect.dispatchAttempt,
        turnId: dispatched.activeTurn.turnId,
        fence,
        settlementAuthority,
        resultRef: "phase0b-workspace-result-1",
      },
      diagnostics,
    );
  }

  get diagnostics(): Readonly<RecoveryDiagnostics> {
    return structuredClone(this.#diagnostics);
  }

  restart(): RecoverableWorkspaceEffect {
    return new RecoverableWorkspaceEffect(
      this.#sessionStorage.restart(),
      this.#workspaceStorage.restart(),
      this.#context,
      this.#diagnostics,
    );
  }

  async snapshot(): Promise<{
    readonly session: SessionAggregateState;
    readonly workspace: WorkspaceAggregateState;
  }> {
    const [session, workspace] = await Promise.all([
      this.#sessionKernel.query(null, (state) => state),
      this.#workspaceKernel.query(null, (state) => state),
    ]);
    return { session, workspace };
  }

  async recover(
    options: RecoverWorkspaceEffectOptions = {},
  ): Promise<RecoverWorkspaceEffectResult> {
    const requestDigest = options.requestDigest ?? this.#context.requestDigest;
    const authority: WorkspaceAuthoritySnapshot = {
      ...this.#context.settlementAuthority,
      ...options.authorityOverrides,
    };
    this.#diagnostics.workspaceLedgerQueries += 1;
    const ledger = await this.#workspaceKernel.query(
      { invocationId: this.#context.invocationId, requestDigest, authority },
      (state, query) => lookupWorkspaceInvocation(
        state,
        query.invocationId,
        query.requestDigest,
        query.authority,
        4_000,
      ),
    );
    if (ledger === null) {
      throw new Error("committed Workspace invocation is missing during recovery");
    }

    const externalCommit = await this.#sessionKernel.execute({
      kind: "record_external_commit",
      commandId: "phase0b-record-workspace-commit",
      expectedEventSequence: 3,
      turnId: this.#context.turnId,
      effectId: this.#context.effectId,
      invocationId: this.#context.invocationId,
      requestDigest: this.#context.requestDigest,
      dispatchAttempt: this.#context.dispatchAttempt,
      fence: this.#context.fence,
      externalCommitId: ledger.result.workspaceCommitId,
      resultRef: this.#context.resultRef,
    });
    const settlement = await this.#sessionKernel.execute({
      kind: "settle_effect",
      commandId: "phase0b-settle-workspace-effect",
      expectedEventSequence: 4,
      turnId: this.#context.turnId,
      effectId: this.#context.effectId,
      invocationId: this.#context.invocationId,
      requestDigest: this.#context.requestDigest,
      dispatchAttempt: this.#context.dispatchAttempt,
      fence: this.#context.fence,
      settlement: {
        kind: "success",
        result: {
          workspaceCommitId: ledger.result.workspaceCommitId,
          revision: ledger.result.revision,
          rootDigest: ledger.result.rootDigest,
        },
      },
    });
    return {
      workspaceResult: ledger.result,
      externalCommit: {
        replayed: externalCommit.replayed,
        version: externalCommit.version,
      },
      settlement: {
        replayed: settlement.replayed,
        version: settlement.version,
      },
    };
  }
}
