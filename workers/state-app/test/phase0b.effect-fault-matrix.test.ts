import { digestBytes, type Digest } from "@circulusd/protocol-types";
import { describe, expect, it } from "vitest";

import type { AggregateAdapter } from "../src/host/contracts.ts";
import { TransactionalAggregateKernel } from "../src/host/kernel.ts";
import {
  applySessionCommand,
  createSessionState,
  migrateSessionState,
  replaySessionPublicEvents,
  turnInputDigest,
  validateSessionState,
  type CreateSessionStateInput,
  type EnqueueTurnCommand,
  type SessionAggregateState,
  type SessionCommand,
  type SessionCommandOutcome,
} from "../src/session/index.ts";
import { RestartableDurableStorage } from "./support/restartable-durable-storage.ts";

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
