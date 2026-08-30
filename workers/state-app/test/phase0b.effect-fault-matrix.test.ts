import {
  digestBytes,
  type Digest,
  type EngineAgentCheckpoint,
  type ReplayPolicy,
} from "@circulusd/protocol-types";
import { describe, expect, it } from "vitest";

import type { AggregateAdapter } from "../src/host/contracts.ts";
import { TransactionalAggregateKernel } from "../src/host/kernel.ts";
import {
  applySessionCommand,
  checkpointDigest,
  createSessionState,
  effectRequestDigest,
  migrateSessionState,
  replaySessionPublicEvents,
  turnInputDigest,
  validateSessionState,
  type CreateSessionStateInput,
  type EnqueueTurnCommand,
  type SessionAggregateState,
  type SessionCommand,
  type SessionCommandOutcome,
  type SessionEffect,
  type SessionFence,
} from "../src/session/index.ts";
import {
  InjectedDurableStorageCrash,
  RestartableDurableStorage,
  type InjectedCommitCrashPhase,
} from "./support/restartable-durable-storage.ts";

const sessionAdapter: AggregateAdapter<
  SessionAggregateState,
  CreateSessionStateInput,
  SessionCommand,
  SessionCommandOutcome
> = {
  kind: "phase0b-reference-session",
  create: createSessionState,
  migrate: migrateSessionState,
  validate: validateSessionState,
  apply: applySessionCommand,
  version: (state) => state.eventSequence,
};

function digest(character: string): Digest {
  return `sha256:${character.repeat(64)}` as Digest;
}

function sessionInitialization(): CreateSessionStateInput {
  return {
    sessionId: "phase0b-session",
    tenantId: "phase0b-tenant",
    userId: "phase0b-user",
    workspaceId: "phase0b-workspace",
    runtimeRevisionDigest: digest("1"),
    policySnapshotDigest: digest("2"),
    emergencyOverlayDigest: digest("3"),
    engineKind: "low-level",
    adapterAbiVersion: 1,
    checkpointSchemaVersion: 1,
    placementGeneration: 4,
    sandboxGeneration: 5,
    authorizationGeneration: 6,
  };
}

async function enqueueCommand(
  overrides: {
    readonly message?: string;
    readonly requestDigest?: Digest;
  } = {},
): Promise<EnqueueTurnCommand> {
  const turnId = "phase0b-turn";
  const input = { message: overrides.message ?? "recover me" };
  const payloadBytes = new TextEncoder().encode(`genesis:${turnId}`);
  return {
    kind: "enqueue_turn",
    commandId: "phase0b-enqueue",
    expectedEventSequence: 0,
    transactionTime: 100,
    turnId,
    input,
    inputDigest: await turnInputDigest(input),
    genesisCheckpoint: {
      kind: "genesis",
      engineKind: "low-level",
      adapterAbiVersion: 1,
      checkpointSchemaVersion: 1,
      runtimeRevisionDigest: digest("1"),
      sessionId: "phase0b-session",
      turnId,
      checkpointSequence: 0,
      predecessorDigest: null,
      payloadEncoding: "opaque-v1",
      payloadBytes,
      payloadDigest: await digestBytes(payloadBytes),
    },
    turnLeaseGeneration: 10,
    leaseExpiresAt: 1_000,
    publicAdmission: {
      authorizationGeneration: 6,
      idempotencyKeyDigest: digest("a"),
      requestDigest: overrides.requestDigest ?? digest("b"),
    },
  };
}

function kernel(storage: RestartableDurableStorage) {
  return new TransactionalAggregateKernel(
    { storage },
    sessionAdapter,
  );
}

const TRANSACTION_TIME = 100;
const DISPATCH_DEADLINE = 900;
const PROVIDER_ROUTE_DIGEST = digest("7");

const lifecycleBoundaries = [
  "turn.accepted",
  "model.prepared",
  "model.dispatched",
  "model.settled",
  "tool.prepared",
  "tool.dispatched",
  "external.commit",
  "tool.settled",
  "turn.completed",
] as const;

type LifecycleBoundary = (typeof lifecycleBoundaries)[number];

const crashPhases = [
  "before-commit",
  "after-commit-before-result",
] as const satisfies readonly InjectedCommitCrashPhase[];

function currentFence(state: SessionAggregateState): SessionFence {
  const activeTurn = state.activeTurn;
  if (activeTurn === null) {
    throw new Error("test requires an active turn");
  }
  return {
    turnLeaseGeneration: activeTurn.turnLeaseGeneration,
    placementGeneration: state.placementGeneration,
    sandboxGeneration: state.sandboxGeneration,
    authorizationGeneration: state.authorizationGeneration,
  };
}

function activeEffect(state: SessionAggregateState): SessionEffect {
  const effect = state.effects.find(
    (candidate) => candidate.effectId === state.activeTurn?.activeEffectId,
  );
  if (effect === undefined) {
    throw new Error("test requires an active effect");
  }
  return effect;
}

async function nextCheckpoint(
  state: SessionAggregateState,
): Promise<EngineAgentCheckpoint> {
  const activeTurn = state.activeTurn;
  if (activeTurn === null) {
    throw new Error("test requires an active turn");
  }
  const checkpointSequence = activeTurn.checkpoint.checkpointSequence + 1;
  const payloadBytes = new Uint8Array([checkpointSequence]);
  return {
    kind: "engine",
    engineKind: state.engineKind,
    adapterAbiVersion: state.adapterAbiVersion,
    checkpointSchemaVersion: state.checkpointSchemaVersion,
    runtimeRevisionDigest: state.runtimeRevisionDigest,
    sessionId: state.sessionId,
    turnId: activeTurn.turnId,
    checkpointSequence,
    predecessorDigest: await checkpointDigest(activeTurn.checkpoint),
    payloadEncoding: "opaque-v1",
    payloadBytes,
    payloadDigest: await digestBytes(payloadBytes),
  };
}

function assertGapFreeState(state: SessionAggregateState): void {
  expect(state.commandReceipts.map((receipt) => receipt.committedEventSequence)).toEqual(
    Array.from({ length: state.eventSequence }, (_, index) => index + 1),
  );
  expect(state.publicEventSequence).toBe(state.publicEvents.length);
  expect(state.publicEvents.map((event) => event.sequence)).toEqual(
    Array.from({ length: state.publicEventSequence }, (_, index) => index + 1),
  );
  expect(state.effects.filter((effect) => effect.phase === "dispatched")).toHaveLength(
    state.effects.some((effect) => effect.phase === "dispatched") ? 1 : 0,
  );
}

async function executeLifecycleFault(
  faultBoundary: LifecycleBoundary,
  crashPhase: InjectedCommitCrashPhase,
) {
  const storage = new RestartableDurableStorage();
  let activeKernel = kernel(storage);
  await activeKernel.initialize(sessionInitialization());
  storage.injectCrashOnMutatingCommit(
    lifecycleBoundaries.indexOf(faultBoundary) + 1,
    crashPhase,
  );

  let crashState: SessionAggregateState | undefined;
  let postCrashReplayFlags: boolean[] | undefined;

  for (const boundary of lifecycleBoundaries) {
    const state = await activeKernel.query(null, (value) => value);
    let command: SessionCommand;

    switch (boundary) {
      case "turn.accepted":
        command = await enqueueCommand();
        break;

      case "model.prepared": {
        if (state.activeTurn === null) {
          throw new Error("model preparation requires an active turn");
        }
        const request = {
          service: "model" as const,
          operation: "complete",
          replayPolicy: "idempotency-key" as const,
          payload: { promptRef: "phase0b-model-prompt" },
        };
        command = {
          kind: "commit_engine_step",
          commandId: "phase0b-model-prepare",
          expectedEventSequence: state.eventSequence,
          turnId: state.activeTurn.turnId,
          fence: currentFence(state),
          transactionTime: TRANSACTION_TIME,
          consumedSettlementEffectId: null,
          effectIdentity: {
            effectId: "phase0b-model-effect",
            invocationId: "phase0b-model-invocation",
          },
          step: {
            kind: "effect_request",
            checkpoint: await nextCheckpoint(state),
            request: {
              ...request,
              requestDigest: await effectRequestDigest(request),
            },
          },
        };
        break;
      }

      case "model.dispatched":
      case "tool.dispatched": {
        if (state.activeTurn === null) {
          throw new Error("effect dispatch requires an active turn");
        }
        const effect = activeEffect(state);
        command = {
          kind: "dispatch_effect",
          commandId: boundary === "model.dispatched"
            ? "phase0b-model-dispatch"
            : "phase0b-tool-dispatch",
          expectedEventSequence: state.eventSequence,
          turnId: state.activeTurn.turnId,
          effectId: effect.effectId,
          invocationId: effect.invocationId,
          requestDigest: effect.requestDigest,
          fence: currentFence(state),
          transactionTime: TRANSACTION_TIME,
          deadline: DISPATCH_DEADLINE,
          providerRouteDigest: PROVIDER_ROUTE_DIGEST,
        };
        break;
      }

      case "model.settled":
      case "tool.settled": {
        if (state.activeTurn === null) {
          throw new Error("effect settlement requires an active turn");
        }
        const effect = activeEffect(state);
        command = {
          kind: "settle_effect",
          commandId: boundary === "model.settled"
            ? "phase0b-model-settle"
            : "phase0b-tool-settle",
          expectedEventSequence: state.eventSequence,
          turnId: state.activeTurn.turnId,
          effectId: effect.effectId,
          invocationId: effect.invocationId,
          requestDigest: effect.requestDigest,
          dispatchAttempt: effect.dispatchAttempt,
          fence: currentFence(state),
          settlement: {
            kind: "success",
            result: boundary === "model.settled"
              ? { responseRef: "phase0b-model-result" }
              : { outputRef: "phase0b-tool-output" },
          },
        };
        break;
      }

      case "tool.prepared": {
        if (state.activeTurn === null) {
          throw new Error("tool preparation requires an active turn");
        }
        const modelEffect = activeEffect(state);
        const request = {
          service: "executor" as const,
          operation: "spawn",
          replayPolicy: "idempotency-key" as const,
          payload: { argv: ["phase0b-tool"] },
        };
        command = {
          kind: "commit_engine_step",
          commandId: "phase0b-tool-prepare",
          expectedEventSequence: state.eventSequence,
          turnId: state.activeTurn.turnId,
          fence: currentFence(state),
          transactionTime: TRANSACTION_TIME,
          consumedSettlementEffectId: modelEffect.effectId,
          effectIdentity: {
            effectId: "phase0b-tool-effect",
            invocationId: "phase0b-tool-invocation",
          },
          step: {
            kind: "effect_request",
            checkpoint: await nextCheckpoint(state),
            request: {
              ...request,
              requestDigest: await effectRequestDigest(request),
            },
          },
        };
        break;
      }

      case "external.commit": {
        if (state.activeTurn === null) {
          throw new Error("external commit requires an active turn");
        }
        const effect = activeEffect(state);
        command = {
          kind: "record_external_commit",
          commandId: "phase0b-tool-external-commit",
          expectedEventSequence: state.eventSequence,
          turnId: state.activeTurn.turnId,
          effectId: effect.effectId,
          invocationId: effect.invocationId,
          requestDigest: effect.requestDigest,
          dispatchAttempt: effect.dispatchAttempt,
          fence: currentFence(state),
          externalCommitId: "phase0b-external-commit",
          resultRef: "phase0b-tool-result",
        };
        break;
      }

      case "turn.completed": {
        if (state.activeTurn === null) {
          throw new Error("turn completion requires an active turn");
        }
        const toolEffect = activeEffect(state);
        command = {
          kind: "commit_engine_step",
          commandId: "phase0b-turn-complete",
          expectedEventSequence: state.eventSequence,
          turnId: state.activeTurn.turnId,
          fence: currentFence(state),
          transactionTime: TRANSACTION_TIME,
          consumedSettlementEffectId: toolEffect.effectId,
          effectIdentity: null,
          step: {
            kind: "turn_complete",
            checkpoint: await nextCheckpoint(state),
            result: { messageRef: "phase0b-assistant-message" },
          },
        };
        break;
      }
    }

    try {
      await activeKernel.execute(command);
    } catch (error) {
      if (
        !(error instanceof InjectedDurableStorageCrash) ||
        error.phase !== crashPhase ||
        boundary !== faultBoundary ||
        crashState !== undefined
      ) {
        throw error;
      }
      crashState = await kernel(storage.restart()).query(null, (value) => value);
      const recovered = await Promise.all([
        kernel(storage.restart()).execute(command),
        kernel(storage.restart()).execute(structuredClone(command)),
      ]);
      postCrashReplayFlags = recovered.map((result) => result.replayed).sort();
      activeKernel = kernel(storage.restart());
    }

    assertGapFreeState(await activeKernel.query(null, (value) => value));
  }

  if (crashState === undefined || postCrashReplayFlags === undefined) {
    throw new Error(`scheduled crash did not fire at ${faultBoundary}`);
  }

  return {
    crashState,
    finalState: await activeKernel.query(null, (value) => value),
    postCrashReplayFlags,
  };
}

async function prepareDispatchedEffect(
  replayPolicy: ReplayPolicy,
  suffix: string,
) {
  const storage = new RestartableDurableStorage();
  const activeKernel = kernel(storage);
  await activeKernel.initialize(sessionInitialization());
  await activeKernel.execute(await enqueueCommand({ message: `recover ${suffix}` }));

  const admitted = await activeKernel.query(null, (value) => value);
  if (admitted.activeTurn === null) {
    throw new Error("effect preparation requires an active turn");
  }
  const request = {
    service: "executor" as const,
    operation: "spawn",
    replayPolicy,
    payload: { argv: ["recover", suffix] },
  };
  await activeKernel.execute({
    kind: "commit_engine_step",
    commandId: `prepare-${suffix}`,
    expectedEventSequence: admitted.eventSequence,
    turnId: admitted.activeTurn.turnId,
    fence: currentFence(admitted),
    transactionTime: TRANSACTION_TIME,
    consumedSettlementEffectId: null,
    effectIdentity: {
      effectId: `effect-${suffix}`,
      invocationId: `invocation-${suffix}`,
    },
    step: {
      kind: "effect_request",
      checkpoint: await nextCheckpoint(admitted),
      request: {
        ...request,
        requestDigest: await effectRequestDigest(request),
      },
    },
  });

  const prepared = await activeKernel.query(null, (value) => value);
  if (prepared.activeTurn === null) {
    throw new Error("effect dispatch requires an active turn");
  }
  const effect = activeEffect(prepared);
  await activeKernel.execute({
    kind: "dispatch_effect",
    commandId: `dispatch-${suffix}`,
    expectedEventSequence: prepared.eventSequence,
    turnId: prepared.activeTurn.turnId,
    effectId: effect.effectId,
    invocationId: effect.invocationId,
    requestDigest: effect.requestDigest,
    fence: currentFence(prepared),
    transactionTime: TRANSACTION_TIME,
    deadline: DISPATCH_DEADLINE,
    providerRouteDigest: PROVIDER_ROUTE_DIGEST,
  });

  return {
    state: await activeKernel.query(null, (value) => value),
    storage,
  };
}

function recoveryCommand(
  state: SessionAggregateState,
  suffix: string,
): SessionCommand {
  if (state.activeTurn === null) {
    throw new Error("effect recovery requires an active turn");
  }
  const effect = activeEffect(state);
  return {
    kind: "recover_effect",
    commandId: `recover-${suffix}`,
    expectedEventSequence: state.eventSequence,
    turnId: state.activeTurn.turnId,
    effectId: effect.effectId,
    invocationId: effect.invocationId,
    requestDigest: effect.requestDigest,
    fence: currentFence(state),
    transactionTime: TRANSACTION_TIME + 1,
    deadline: DISPATCH_DEADLINE + 1,
    providerRequestId: `provider-${suffix}`,
    providerRouteDigest: PROVIDER_ROUTE_DIGEST,
  };
}

const lifecycleFaultCases = lifecycleBoundaries.flatMap((boundary) =>
  crashPhases.map((phase) => [boundary, phase] as const)
);

const recoveryCases = [
  {
    replayPolicy: "safe",
    action: "retry",
    effectPhase: "dispatched",
    publicEventSequence: 2,
  },
  {
    replayPolicy: "idempotency-key",
    action: "retry",
    effectPhase: "dispatched",
    publicEventSequence: 2,
  },
  {
    replayPolicy: "never",
    action: "interrupted",
    effectPhase: "settled",
    publicEventSequence: 3,
  },
  {
    replayPolicy: "confirm",
    action: "blocked",
    effectPhase: "blocked",
    publicEventSequence: 3,
  },
] as const satisfies readonly {
  readonly replayPolicy: ReplayPolicy;
  readonly action: "retry" | "interrupted" | "blocked";
  readonly effectPhase: SessionEffect["phase"];
  readonly publicEventSequence: number;
}[];

const recoveryFaultCases = recoveryCases.flatMap((recovery) =>
  crashPhases.map((phase) => ({ ...recovery, phase }))
);

// Provider-start response loss is covered by phase0b.dispatch-start.test.ts.
// A real durable external invocation ledger and no-repeat mutation recovery are
// covered separately by phase0b.cross-do-recovery.test.ts. This suite owns the
// Session transaction boundaries and pre-provider dispatch recovery decisions.
describe("Phase 0B reference Session durable-transition matrix", () => {
  it.each(lifecycleFaultCases)(
    "recovers the %s / %s boundary without a duplicate transition",
    async (boundary, phase) => {
      const result = await executeLifecycleFault(boundary, phase);
      const boundarySequence = lifecycleBoundaries.indexOf(boundary) + 1;
      expect(result.crashState.eventSequence).toBe(
        phase === "before-commit" ? boundarySequence - 1 : boundarySequence,
      );
      expect(result.postCrashReplayFlags).toEqual(
        phase === "before-commit" ? [false, true] : [true, true],
      );
      expect(result.finalState).toMatchObject({
        eventSequence: 9,
        publicEventSequence: 7,
        activeTurn: null,
        terminalTurns: [{ turnId: "phase0b-turn", status: "completed" }],
      });
      assertGapFreeState(result.finalState);
    },
  );

  it("reconstructs the exact durable public lifecycle after a scheduled mid-run crash", async () => {
    const { finalState } = await executeLifecycleFault(
      "external.commit",
      "after-commit-before-result",
    );
    expect(finalState.publicEvents.map((event) => event.type)).toEqual([
      "turn.accepted",
      "model.effect.prepared",
      "model.settled",
      "tool.effect.prepared",
      "tool.externally_committed",
      "tool.settled",
      "turn.completed",
    ]);
    expect(finalState.effects).toEqual([
      expect.objectContaining({
        effectId: "phase0b-model-effect",
        phase: "settled",
        consumedAtCheckpointSequence: 2,
      }),
      expect.objectContaining({
        effectId: "phase0b-tool-effect",
        phase: "settled",
        consumedAtCheckpointSequence: 3,
        externalCommitId: "phase0b-external-commit",
      }),
    ]);
  });

  it.each(recoveryFaultCases)(
    "applies pre-provider $replayPolicy recovery once across $phase response loss",
    async ({
      replayPolicy,
      action,
      effectPhase,
      publicEventSequence,
      phase,
    }) => {
      const suffix = `${replayPolicy}-${phase}`;
      const { storage, state } = await prepareDispatchedEffect(replayPolicy, suffix);
      const priorEffect = activeEffect(state);
      const command = recoveryCommand(state, suffix);
      storage.injectCrashOnce(phase);

      await expect(kernel(storage).execute(command)).rejects.toMatchObject({
        name: "InjectedDurableStorageCrash",
        phase,
      });
      const crashState = await kernel(storage.restart()).query(null, (value) => value);
      expect(crashState.eventSequence).toBe(phase === "before-commit" ? 3 : 4);

      const results = await Promise.all([
        kernel(storage.restart()).execute(command),
        kernel(storage.restart()).execute(structuredClone(command)),
      ]);
      expect(results.map((result) => result.replayed).sort()).toEqual(
        phase === "before-commit" ? [false, true] : [true, true],
      );
      expect(results.every((result) =>
        result.outcome.kind === "effect_recovered" && result.outcome.action === action
      )).toBe(true);

      const recovered = await kernel(storage.restart()).query(null, (value) => value);
      const effect = activeEffect(recovered);
      expect(recovered).toMatchObject({
        eventSequence: 4,
        publicEventSequence,
      });
      expect(effect).toMatchObject({
        effectId: priorEffect.effectId,
        invocationId: priorEffect.invocationId,
        requestDigest: priorEffect.requestDigest,
        phase: effectPhase,
        dispatchAttempt: action === "retry" ? 2 : 1,
      });
      expect(priorEffect.lastDispatch?.start).toBeNull();
      if (replayPolicy === "never") {
        expect(effect.settlement).toMatchObject({ kind: "interrupted_unknown" });
      }
      if (replayPolicy === "confirm") {
        expect(recovered.activeTurn?.status).toBe("needs_confirmation");
        expect(recovered.publicEvents.at(-1)?.type).toBe("turn.needs_confirmation");
      }
      assertGapFreeState(recovered);
    },
  );

  it("lets exactly one of 64 recovery workers advance the durable attempt", async () => {
    const { storage, state } = await prepareDispatchedEffect(
      "idempotency-key",
      "concurrent",
    );
    const command = recoveryCommand(state, "concurrent");
    const results = await Promise.all(
      Array.from({ length: 64 }, () =>
        kernel(storage.restart()).execute(structuredClone(command))
      ),
    );
    expect(results.filter((result) => !result.replayed)).toHaveLength(1);
    expect(results.filter((result) => result.replayed)).toHaveLength(63);
    expect(results.every((result) =>
      result.outcome.kind === "effect_recovered" && result.outcome.action === "retry"
    )).toBe(true);

    const recovered = await kernel(storage.restart()).query(null, (value) => value);
    expect(activeEffect(recovered)).toMatchObject({
      phase: "dispatched",
      dispatchAttempt: 2,
      invocationId: "invocation-concurrent",
    });
    assertGapFreeState(recovered);
  });

  it("admits and dispatches at most one of 64 competing effect programs", async () => {
    const storage = new RestartableDurableStorage();
    const initialKernel = kernel(storage);
    await initialKernel.initialize(sessionInitialization());
    await initialKernel.execute(await enqueueCommand({ message: "competing effects" }));
    const admitted = await initialKernel.query(null, (value) => value);
    if (admitted.activeTurn === null) {
      throw new Error("competing effects require an active turn");
    }
    const checkpoint = await nextCheckpoint(admitted);
    const preparations = await Promise.all(
      Array.from({ length: 64 }, async (_, index): Promise<SessionCommand> => {
        const request = {
          service: "executor" as const,
          operation: "spawn",
          replayPolicy: "safe" as const,
          payload: { argv: ["candidate", index] },
        };
        return {
          kind: "commit_engine_step",
          commandId: `competing-prepare-${index}`,
          expectedEventSequence: admitted.eventSequence,
          turnId: admitted.activeTurn.turnId,
          fence: currentFence(admitted),
          transactionTime: TRANSACTION_TIME,
          consumedSettlementEffectId: null,
          effectIdentity: {
            effectId: `competing-effect-${index}`,
            invocationId: `competing-invocation-${index}`,
          },
          step: {
            kind: "effect_request",
            checkpoint,
            request: {
              ...request,
              requestDigest: await effectRequestDigest(request),
            },
          },
        };
      }),
    );
    const preparationResults = await Promise.allSettled(
      preparations.map((command) =>
        kernel(storage.restart()).execute(structuredClone(command))
      ),
    );
    expect(preparationResults.filter((result) => result.status === "fulfilled"))
      .toHaveLength(1);
    expect(preparationResults.filter((result) => result.status === "rejected"))
      .toHaveLength(63);

    const prepared = await kernel(storage.restart()).query(null, (value) => value);
    if (prepared.activeTurn === null) {
      throw new Error("competing dispatches require an active turn");
    }
    expect(prepared.effects).toHaveLength(1);
    expect(prepared.activeTurn.activeEffectId).toBe(prepared.effects[0]?.effectId);
    const effect = activeEffect(prepared);
    const dispatches = Array.from({ length: 64 }, (_, index): SessionCommand => ({
      kind: "dispatch_effect",
      commandId: `competing-dispatch-${index}`,
      expectedEventSequence: prepared.eventSequence,
      turnId: prepared.activeTurn.turnId,
      effectId: effect.effectId,
      invocationId: effect.invocationId,
      requestDigest: effect.requestDigest,
      fence: currentFence(prepared),
      transactionTime: TRANSACTION_TIME,
      deadline: DISPATCH_DEADLINE,
      providerRequestId: `competing-provider-${index}`,
      providerRouteDigest: PROVIDER_ROUTE_DIGEST,
    }));
    const dispatchResults = await Promise.allSettled(
      dispatches.map((command) =>
        kernel(storage.restart()).execute(structuredClone(command))
      ),
    );
    expect(dispatchResults.filter((result) => result.status === "fulfilled"))
      .toHaveLength(1);
    expect(dispatchResults.filter((result) => result.status === "rejected"))
      .toHaveLength(63);

    const dispatched = await kernel(storage.restart()).query(null, (value) => value);
    expect(dispatched.effects).toEqual([
      expect.objectContaining({ phase: "dispatched", dispatchAttempt: 1 }),
    ]);
    expect(dispatched.commandReceipts.filter((receipt) =>
      receipt.outcome.kind === "effect_dispatched"
    )).toHaveLength(1);
    assertGapFreeState(dispatched);
  });

  it("settles a Session-recorded external commit without reopening dispatch", async () => {
    const { storage, state } = await prepareDispatchedEffect("safe", "external-proof");
    if (state.activeTurn === null) {
      throw new Error("external commit requires an active turn");
    }
    const effect = activeEffect(state);
    await kernel(storage).execute({
      kind: "record_external_commit",
      commandId: "record-external-proof",
      expectedEventSequence: state.eventSequence,
      turnId: state.activeTurn.turnId,
      effectId: effect.effectId,
      invocationId: effect.invocationId,
      requestDigest: effect.requestDigest,
      dispatchAttempt: effect.dispatchAttempt,
      fence: currentFence(state),
      externalCommitId: "external-proof-commit",
      resultRef: "external-proof-result",
    });

    const committed = await kernel(storage.restart()).query(null, (value) => value);
    if (committed.activeTurn === null) {
      throw new Error("external settlement requires an active turn");
    }
    expect(activeEffect(committed)).toMatchObject({
      phase: "externally_committed",
      dispatchAttempt: 1,
      externalCommitId: "external-proof-commit",
      resultRef: "external-proof-result",
    });
    await expect(
      kernel(storage.restart()).execute(recoveryCommand(committed, "external-proof")),
    ).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
    expect(
      (await kernel(storage.restart()).query(null, (value) => value)).eventSequence,
    ).toBe(4);

    const committedEffect = activeEffect(committed);
    await kernel(storage.restart()).execute({
      kind: "settle_effect",
      commandId: "settle-external-proof",
      expectedEventSequence: committed.eventSequence,
      turnId: committed.activeTurn.turnId,
      effectId: committedEffect.effectId,
      invocationId: committedEffect.invocationId,
      requestDigest: committedEffect.requestDigest,
      dispatchAttempt: committedEffect.dispatchAttempt,
      fence: currentFence(committed),
      settlement: {
        kind: "success",
        result: { resultRef: committedEffect.resultRef },
      },
    });
    const settled = await kernel(storage.restart()).query(null, (value) => value);
    expect(activeEffect(settled)).toMatchObject({
      phase: "settled",
      dispatchAttempt: 1,
      externalCommitId: "external-proof-commit",
    });
    expect(settled.commandReceipts.filter((receipt) =>
      receipt.outcome.kind === "effect_dispatched"
    )).toHaveLength(1);
    expect(settled.commandReceipts.filter((receipt) =>
      receipt.outcome.kind === "effect_recovered"
    )).toHaveLength(0);
    assertGapFreeState(settled);
  });
});

describe("Phase 0B reference-only Durable Object commit fault matrix", () => {
  it("leaves every staged initialization write absent after a pre-commit crash", async () => {
    const storage = new RestartableDurableStorage();
    expect(storage.evidence).toMatchObject({
      referenceOnly: true,
      productionEligible: false,
      conformanceClaimed: false,
    });
    storage.injectCrashOnce("before-commit");

    await expect(kernel(storage).initialize(sessionInitialization())).rejects.toMatchObject({
      name: "InjectedDurableStorageCrash",
      phase: "before-commit",
    });
    expect(storage.durableEntryCount).toBe(0);

    await expect(
      kernel(storage.restart()).initialize(sessionInitialization()),
    ).resolves.toEqual({ version: 0, replayed: false });
  });

  it("preserves an atomic post-commit result for idempotent replay and rejects conflict", async () => {
    const storage = new RestartableDurableStorage();
    const initialKernel = kernel(storage);
    await initialKernel.initialize(sessionInitialization());
    const command = await enqueueCommand();
    storage.injectCrashOnce("after-commit-before-result");

    await expect(initialKernel.execute(command)).rejects.toMatchObject({
      name: "InjectedDurableStorageCrash",
      phase: "after-commit-before-result",
    });

    const restartedKernel = kernel(storage.restart());
    const recovered = await restartedKernel.query(null, (state) => state);
    expect(recovered).toMatchObject({
      eventSequence: 1,
      publicEventSequence: 1,
      commandReceipts: [{ commandId: command.commandId, committedEventSequence: 1 }],
      turnAdmissionReceipts: [{ turnId: command.turnId, publicEventSequence: 1 }],
    });
    expect(recovered.publicEvents.map((event) => event.sequence)).toEqual([1]);

    await expect(restartedKernel.execute(command)).resolves.toMatchObject({
      version: 1,
      replayed: true,
    });
    const admission = command.publicAdmission;
    if (admission === undefined) {
      throw new Error("test command requires a public admission");
    }
    await expect(
      restartedKernel.execute({
        ...command,
        publicAdmission: {
          ...admission,
          requestDigest: digest("c"),
        },
      }),
    ).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
  });

  it("lets concurrent recovery workers commit one transition with a gap-free event cursor", async () => {
    const storage = new RestartableDurableStorage();
    const initialKernel = kernel(storage);
    await initialKernel.initialize(sessionInitialization());
    const command = await enqueueCommand();
    storage.injectCrashOnce("before-commit");

    await expect(initialKernel.execute(command)).rejects.toMatchObject({
      phase: "before-commit",
    });
    await expect(
      kernel(storage.restart()).query(null, (state) => state.eventSequence),
    ).resolves.toBe(0);

    const firstRecovery = kernel(storage.restart());
    const secondRecovery = kernel(storage.restart());
    const results = await Promise.all([
      firstRecovery.execute(command),
      secondRecovery.execute(structuredClone(command)),
    ]);
    expect(results.map((result) => result.replayed).sort()).toEqual([false, true]);
    expect(results.every((result) => result.version === 1)).toBe(true);

    const recovered = await kernel(storage.restart()).query(null, (state) => state);
    const replay = replaySessionPublicEvents(recovered, 0, 16);
    expect(recovered.eventSequence).toBe(1);
    expect(recovered.commandReceipts).toHaveLength(1);
    expect(replay.snapshot.lastEventSequence).toBe(1);
    expect(replay.events.map((event) => event.sequence)).toEqual([1]);
  });
});
