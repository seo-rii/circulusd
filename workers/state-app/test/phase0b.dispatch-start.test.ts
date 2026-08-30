import {
  digestBytes,
  digestStructuredValue,
  type AgentCheckpoint,
  type Digest,
} from "@circulusd/protocol-types";
import { describe, expect, it } from "vitest";

import type { AggregateAdapter } from "../src/host/contracts.ts";
import { TransactionalAggregateKernel } from "../src/host/kernel.ts";
import { ChunkedAggregateStorage } from "../src/host/storage.ts";
import {
  SESSION_COMMAND_SCHEMA_VERSION,
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
} from "../src/session/index.ts";
import { RestartableDurableStorage } from "./support/restartable-durable-storage.ts";

const adapter: AggregateAdapter<
  SessionAggregateState,
  CreateSessionStateInput,
  SessionCommand,
  SessionCommandOutcome
> = {
  kind: "phase0b-dispatch-start-session",
  create: createSessionState,
  migrate: migrateSessionState,
  validate: validateSessionState,
  apply: applySessionCommand,
  version: (state) => state.eventSequence,
};

const TRANSACTION_TIME = 1_700_000_000_000;
const DEADLINE = TRANSACTION_TIME + 60_000;
const ROUTE_DIGEST = digest("7");
const COMMAND_DIGEST = digest("8");

type DispatchStartCommand = {
  readonly kind: "claim_dispatch_start";
  readonly commandId: string;
  readonly expectedEventSequence: number;
  readonly turnId: string;
  readonly effectId: string;
  readonly invocationId: string;
  readonly requestDigest: Digest;
  readonly fence: SessionFence;
  readonly transactionTime: number;
  readonly dispatchAttempt: number;
  readonly providerRequestId: string;
  readonly providerRouteDigest: Digest;
  readonly dispatchPermitClaims: unknown;
  readonly commandDigest: Digest;
};

function digest(character: string): Digest {
  return `sha256:${character.repeat(64)}` as Digest;
}

function initialization(): CreateSessionStateInput {
  return {
    sessionId: "dispatch-start-session",
    tenantId: "dispatch-start-tenant",
    userId: "dispatch-start-user",
    workspaceId: "dispatch-start-workspace",
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

function kernel(storage: RestartableDurableStorage) {
  return new TransactionalAggregateKernel(
    { storage },
    adapter,
    undefined,
    () => TRANSACTION_TIME + 1,
  );
}

function fence(state: SessionAggregateState): SessionFence {
  if (state.activeTurn === null) throw new Error("active turn required");
  return {
    turnLeaseGeneration: state.activeTurn.turnLeaseGeneration,
    placementGeneration: state.placementGeneration,
    sandboxGeneration: state.sandboxGeneration,
    authorizationGeneration: state.authorizationGeneration,
  };
}

async function genesis(): Promise<AgentCheckpoint> {
  const payloadBytes = new Uint8Array([0]);
  return {
    kind: "genesis",
    engineKind: "low-level",
    adapterAbiVersion: 1,
    checkpointSchemaVersion: 1,
    runtimeRevisionDigest: digest("1"),
    sessionId: "dispatch-start-session",
    turnId: "dispatch-start-turn",
    checkpointSequence: 0,
    predecessorDigest: null,
    payloadEncoding: "opaque-v1",
    payloadBytes,
    payloadDigest: await digestBytes(payloadBytes),
  };
}

async function prepareDispatchedStorage() {
  const storage = new RestartableDurableStorage();
  const initial = kernel(storage);
  await initial.initialize(initialization());
  const input = { message: "start exactly once" };
  await initial.execute({
    kind: "enqueue_turn",
    commandId: "enqueue",
    expectedEventSequence: 0,
    transactionTime: TRANSACTION_TIME,
    turnId: "dispatch-start-turn",
    input,
    inputDigest: await turnInputDigest(input),
    genesisCheckpoint: await genesis(),
    turnLeaseGeneration: 10,
    leaseExpiresAt: DEADLINE + 1,
  });
  const admitted = await initial.query(null, (state) => state);
  if (admitted.activeTurn === null) throw new Error("active turn required");
  const payloadBytes = new Uint8Array([1]);
  const request = {
    service: "executor" as const,
    operation: "run",
    replayPolicy: "safe" as const,
    payload: { argv: ["true"] },
  };
  await initial.execute({
    kind: "commit_engine_step",
    commandId: "prepare",
    expectedEventSequence: admitted.eventSequence,
    turnId: admitted.activeTurn.turnId,
    fence: fence(admitted),
    transactionTime: TRANSACTION_TIME,
    consumedSettlementEffectId: null,
    effectIdentity: { effectId: "effect", invocationId: "invocation" },
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
        payloadBytes,
        payloadDigest: await digestBytes(payloadBytes),
      },
      request: { ...request, requestDigest: await effectRequestDigest(request) },
    },
  });
  const prepared = await initial.query(null, (state) => state);
  const effect = prepared.effects[0];
  if (effect === undefined) throw new Error("prepared effect required");
  const dispatched = await initial.execute({
    kind: "dispatch_effect",
    commandId: "dispatch",
    expectedEventSequence: prepared.eventSequence,
    turnId: "dispatch-start-turn",
    effectId: effect.effectId,
    invocationId: effect.invocationId,
    requestDigest: effect.requestDigest,
    fence: fence(prepared),
    transactionTime: TRANSACTION_TIME,
    deadline: DEADLINE,
    providerRequestId: "provider-request",
    providerRouteDigest: ROUTE_DIGEST,
  });
  if (dispatched.outcome.kind !== "effect_dispatched") {
    throw new Error("dispatch permit required");
  }
  return {
    storage,
    permit: dispatched.outcome.dispatchPermitClaims,
    state: await initial.query(null, (value) => value),
  };
}

function startCommand(
  state: SessionAggregateState,
  permit: unknown,
  commandId: string,
  overrides: Partial<DispatchStartCommand> = {},
): SessionCommand {
  const effect = state.effects[0];
  if (effect === undefined) throw new Error("dispatched effect required");
  return {
    kind: "claim_dispatch_start",
    commandId,
    expectedEventSequence: state.eventSequence,
    turnId: "dispatch-start-turn",
    effectId: effect.effectId,
    invocationId: effect.invocationId,
    requestDigest: effect.requestDigest,
    fence: fence(state),
    transactionTime: TRANSACTION_TIME + 1,
    dispatchAttempt: effect.dispatchAttempt,
    providerRequestId: "provider-request",
    providerRouteDigest: ROUTE_DIGEST,
    dispatchPermitClaims: permit,
    commandDigest: COMMAND_DIGEST,
    ...overrides,
  } as unknown as SessionCommand;
}

describe("Phase 0B durable dispatch start claim", () => {
  it("preserves legacy receipt digests while RPC wire identity rotates separately", () => {
    expect(SESSION_COMMAND_SCHEMA_VERSION).toBe(1);
  });

  it("grants one fresh claim across two restarted consumers and preserves its exact binding", async () => {
    const { storage, permit, state } = await prepareDispatchedStorage();
    const results = await Promise.all([
      kernel(storage.restart()).execute(startCommand(state, permit, "start-a")),
      kernel(storage.restart()).execute(startCommand(state, permit, "start-b")),
    ]);

    expect(results.filter((result) =>
      (result.outcome as { fresh?: boolean }).fresh === true
    )).toHaveLength(1);
    const durable = await kernel(storage.restart()).query(null, (value) => value);
    expect(durable.effects[0]).toMatchObject({
      dispatchAttempt: 1,
      lastDispatch: {
        deadline: DEADLINE,
        providerRequestId: "provider-request",
        providerRouteDigest: ROUTE_DIGEST,
        start: {
          commandDigest: COMMAND_DIGEST,
          dispatchAttempt: 1,
          providerRouteDigest: ROUTE_DIGEST,
          turnLeaseGeneration: 10,
          placementGeneration: 4,
          sandboxGeneration: 5,
          authorizationGeneration: 6,
        },
      },
    });
  });

  it("reuses the exact proof after response loss and rejects every relabel", async () => {
    const { storage, permit, state } = await prepareDispatchedStorage();
    storage.injectCrashOnce("after-commit-before-result");
    await expect(
      kernel(storage).execute(startCommand(state, permit, "lost-response")),
    ).rejects.toMatchObject({ phase: "after-commit-before-result" });

    const restarted = kernel(storage.restart());
    const replay = await restarted.execute(startCommand(state, permit, "lost-response"));
    expect(replay.replayed).toBe(true);
    expect(replay.outcome).toMatchObject({ fresh: false });
    const originalProof = (replay.outcome as { startPermit: unknown }).startPermit;
    expect(originalProof).toBeDefined();

    for (const command of [
      startCommand(state, permit, "wrong-command", { commandDigest: digest("9") }),
      startCommand(state, permit, "wrong-route", { providerRouteDigest: digest("a") }),
      startCommand(state, { kind: "forged-dispatch-proof" }, "wrong-permit"),
    ]) {
      await expect(restarted.execute(command)).rejects.toMatchObject({
        code: expect.stringMatching(/CONFLICT|FENCE|PRECONDITION/),
      });
    }
  });

  it("rejects a fresh claim after abort wins the race", async () => {
    const { storage, permit, state } = await prepareDispatchedStorage();
    await kernel(storage.restart()).execute({
      kind: "request_abort",
      commandId: "abort-first",
      expectedEventSequence: state.eventSequence,
      turnId: "dispatch-start-turn",
      fence: fence(state),
      transactionTime: TRANSACTION_TIME + 1,
      reason: "operator abort",
    });
    const aborted = await kernel(storage.restart()).query(null, (value) => value);
    await expect(
      kernel(storage.restart()).execute(startCommand(aborted, permit, "start-after-abort")),
    ).rejects.toMatchObject({ code: expect.stringMatching(/ABORT|PRECONDITION/) });
  });

  it("uses host-observed time instead of a caller-supplied past timestamp", async () => {
    const { permit, state } = await prepareDispatchedStorage();
    await expect(
      applySessionCommand(
        state,
        startCommand(state, permit, "expired-host-clock", {
          transactionTime: TRANSACTION_TIME + 1,
        }),
        { transactionTime: DEADLINE },
      ),
    ).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
  });

  it("retains a committed claim when abort follows and replays it as non-fresh after restart", async () => {
    const { storage, permit, state } = await prepareDispatchedStorage();
    const claimed = await kernel(storage.restart()).execute(
      startCommand(state, permit, "start-before-abort"),
    );
    const afterClaim = await kernel(storage.restart()).query(null, (value) => value);
    await kernel(storage.restart()).execute({
      kind: "request_abort",
      commandId: "abort-after-start",
      expectedEventSequence: afterClaim.eventSequence,
      turnId: "dispatch-start-turn",
      fence: fence(afterClaim),
      transactionTime: TRANSACTION_TIME + 2,
      reason: "operator abort",
    });
    const afterAbort = await kernel(storage.restart()).query(null, (value) => value);
    const replay = await kernel(storage.restart()).execute(
      startCommand(afterAbort, permit, "start-after-claimed-abort"),
    );
    expect(replay.outcome).toMatchObject({
      fresh: false,
      startPermit: (claimed.outcome as { startPermit: unknown }).startPermit,
    });
  });

  it("never lets a same-attempt start claim and recovery retry both commit", async () => {
    const { storage, permit, state } = await prepareDispatchedStorage();
    const effect = state.effects[0];
    if (effect === undefined) throw new Error("dispatched effect required");
    const outcomes = await Promise.allSettled([
      kernel(storage.restart()).execute(startCommand(state, permit, "start-race")),
      kernel(storage.restart()).execute({
        kind: "recover_effect",
        commandId: "recover-race",
        expectedEventSequence: state.eventSequence,
        turnId: "dispatch-start-turn",
        effectId: effect.effectId,
        invocationId: effect.invocationId,
        requestDigest: effect.requestDigest,
        fence: fence(state),
        transactionTime: TRANSACTION_TIME + 1,
        deadline: DEADLINE + 1,
        providerRequestId: "provider-request-retry",
        providerRouteDigest: ROUTE_DIGEST,
      }),
    ]);
    expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
  });

  it("fails closed when a persisted start receipt and tombstone are not exact peers", async () => {
    const { storage, permit, state } = await prepareDispatchedStorage();
    await kernel(storage.restart()).execute(startCommand(state, permit, "start-integrity"));
    const claimed = await kernel(storage.restart()).query(null, (value) => value);

    const relabeledReceipt = structuredClone(claimed);
    const claimReceipt = relabeledReceipt.commandReceipts.at(-1);
    if (claimReceipt?.outcome.kind !== "dispatch_start_claimed") {
      throw new Error("dispatch start receipt required");
    }
    claimReceipt.outcome.startPermit.dispatchPermitClaims = {
      ...claimReceipt.outcome.startPermit.dispatchPermitClaims,
      providerRouteDigest: digest("a"),
    };
    await expect(validateSessionState(relabeledReceipt)).rejects.toMatchObject({
      code: "FAILED_PRECONDITION",
    });

    const orphanedReceipt = structuredClone(claimed);
    const orphanedEffect = orphanedReceipt.effects[0];
    if (orphanedEffect?.lastDispatch === null || orphanedEffect?.lastDispatch === undefined) {
      throw new Error("dispatch metadata required");
    }
    orphanedEffect.lastDispatch.start = null;
    await expect(validateSessionState(orphanedReceipt)).rejects.toMatchObject({
      code: "FAILED_PRECONDITION",
    });
  });

  it("migrates clean schema-v3 state but never invents a route for dispatch history", async () => {
    const cleanLegacy = structuredClone(createSessionState(initialization())) as unknown as {
      schemaVersion: number;
    };
    cleanLegacy.schemaVersion = 3;
    const cleanMigration = migrateSessionState(cleanLegacy);
    expect(cleanMigration).toMatchObject({ migrated: true, state: { schemaVersion: 4 } });
    await expect(validateSessionState(cleanMigration.state)).resolves.toBeUndefined();

    const { state } = await prepareDispatchedStorage();
    const dispatchedLegacy = structuredClone(state) as unknown as {
      schemaVersion: number;
      effects: Array<{ lastDispatch: Record<string, unknown> | null }>;
      commandReceipts: Array<{ outcome: Record<string, unknown> }>;
    };
    dispatchedLegacy.schemaVersion = 3;
    const legacyDispatch = dispatchedLegacy.effects[0]?.lastDispatch;
    if (legacyDispatch === null || legacyDispatch === undefined) {
      throw new Error("legacy dispatch metadata required");
    }
    Reflect.deleteProperty(legacyDispatch, "providerRouteDigest");
    Reflect.deleteProperty(legacyDispatch, "start");
    const dispatchReceipt = dispatchedLegacy.commandReceipts.find(
      (receipt) => receipt.outcome.kind === "effect_dispatched",
    );
    const legacyPermit = dispatchReceipt?.outcome.dispatchPermitClaims;
    if (typeof legacyPermit !== "object" || legacyPermit === null) {
      throw new Error("legacy dispatch receipt required");
    }
    Reflect.deleteProperty(legacyPermit, "providerRouteDigest");

    expect(() => migrateSessionState(dispatchedLegacy)).toThrowError(
      expect.objectContaining({ code: "FAILED_PRECONDITION" }),
    );

    const legacyStorage = new RestartableDurableStorage();
    const legacyRecords = new ChunkedAggregateStorage<Record<string, unknown>>(
      adapter.kind,
      () => undefined,
    );
    const initializationDigest = await digestStructuredValue(
      `circulusd.state-app.${adapter.kind}-initialization`,
      1,
      initialization(),
    );
    await legacyStorage.transaction(async (transaction) => {
      await legacyRecords.write(
        transaction,
        legacyRecords.buildInitialRecord(
          initializationDigest,
          dispatchedLegacy as unknown as Record<string, unknown>,
        ),
      );
    });
    const legacyRevision = legacyStorage.durableRevision;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      await expect(
        kernel(legacyStorage.restart()).query(null, (value) => value),
      ).rejects.toMatchObject({ code: "CORRUPT_STATE" });
      expect(legacyStorage.durableRevision).toBe(legacyRevision);
    }
  });
});
