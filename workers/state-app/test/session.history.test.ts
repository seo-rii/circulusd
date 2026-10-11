import { digestBytes, type AgentCheckpoint, type Digest } from "@circulusd/protocol-types";
import { describe, expect, it } from "vitest";

import {
  applySessionCommand, createSessionState, effectRequestDigest,
  planSessionHistoryReads, replaySessionPublicEvents, turnInputDigest, validateSessionState,
  SESSION_HISTORY_HOT_COMMANDS, SESSION_HISTORY_HOT_PUBLIC_EVENTS,
  type SessionArchiveDelta, type SessionCommand,
  type SessionHistoryWitness,
} from "../src/session/index.ts";

const digest = (character: string): Digest => `sha256:${character.repeat(64)}`;

function fixture() {
  let state = createSessionState({
    sessionId: "history", tenantId: "tenant", userId: "user", workspaceId: "workspace",
    runtimeRevisionDigest: digest("1"), policySnapshotDigest: digest("2"), emergencyOverlayDigest: digest("3"),
    engineKind: "low-level", adapterAbiVersion: 1, checkpointSchemaVersion: 1,
    placementGeneration: 1, sandboxGeneration: 1, authorizationGeneration: 1,
  });
  const archive: SessionArchiveDelta = {
    commandReceipts: [], publicEvents: [], terminalTurns: [], effects: [],
    turnAdmissionReceipts: [], turnIdentities: [],
  };
  const commands: SessionCommand[] = [];
  function witness(command: SessionCommand): SessionHistoryWitness {
    const plan = planSessionHistoryReads(state, command);
    const history: SessionHistoryWitness = {};
    if (plan.commandId !== undefined) history.command = {
      commandId: plan.commandId,
      receipt: archive.commandReceipts.find((receipt) => receipt.commandId === plan.commandId) ?? null,
    };
    if (plan.idempotencyKeyDigest !== undefined) history.admission = {
      idempotencyKeyDigest: plan.idempotencyKeyDigest,
      receipt: archive.turnAdmissionReceipts.find((receipt) => receipt.idempotencyKeyDigest === plan.idempotencyKeyDigest) ?? null,
    };
    if (plan.turnId !== undefined) history.turn = {
      turnId: plan.turnId, record: archive.turnIdentities.find((turn) => turn.turnId === plan.turnId) ?? null,
    };
    if (plan.effectId !== undefined) history.effect = {
      effectId: plan.effectId, record: archive.effects.find((effect) => effect.effectId === plan.effectId) ?? null,
    };
    if (plan.invocationId !== undefined) {
      const effect = archive.effects.find((effect) => effect.invocationId === plan.invocationId);
      history.invocation = {
        invocationId: plan.invocationId,
        record: effect === undefined ? null : { effectId: effect.effectId, invocationId: effect.invocationId },
      };
    }
    if (plan.issuingEventSequence !== undefined) history.issuingReceipt = {
      eventSequence: plan.issuingEventSequence,
      receipt: archive.commandReceipts.find((receipt) => receipt.committedEventSequence === plan.issuingEventSequence) ?? null,
    };
    return history;
  }
  async function execute(command: SessionCommand) {
    const result = await applySessionCommand(state, command, { transactionTime: 100, history: witness(command) });
    state = result.state;
    if (result.archiveDelta !== undefined) {
      for (const key of Object.keys(archive) as (keyof SessionArchiveDelta)[]) {
        (archive[key] as unknown[]).push(...result.archiveDelta[key]);
      }
    }
    commands.push(structuredClone(command));
    return result;
  }
  function fence() {
    return {
      turnLeaseGeneration: state.activeTurn!.turnLeaseGeneration,
      placementGeneration: state.placementGeneration, sandboxGeneration: state.sandboxGeneration,
      authorizationGeneration: state.authorizationGeneration,
    };
  }
  async function checkpoint(turnId?: string): Promise<AgentCheckpoint> {
    const sequence = turnId === undefined ? state.activeTurn!.checkpoint.checkpointSequence + 1 : 0;
    const id = turnId ?? state.activeTurn!.turnId;
    const payloadBytes = new TextEncoder().encode(`${id}:${sequence}`);
    const metadata = {
      engineKind: state.engineKind, adapterAbiVersion: 1, checkpointSchemaVersion: 1,
      runtimeRevisionDigest: state.runtimeRevisionDigest, sessionId: state.sessionId,
      turnId: id, payloadEncoding: "opaque-v1" as const, payloadBytes,
      payloadDigest: await digestBytes(payloadBytes),
    };
    return turnId === undefined
      ? { ...metadata, kind: "engine", checkpointSequence: sequence, predecessorDigest: state.activeTurn!.checkpointChainDigest! }
      : { ...metadata, kind: "genesis", checkpointSequence: 0, predecessorDigest: null };
  }
  async function admission(turnId: string, publicly = true): Promise<SessionCommand> {
    const input = { message: turnId };
    return {
      kind: "enqueue_turn", commandId: `admit:${turnId}`, expectedEventSequence: state.eventSequence,
      transactionTime: 100, turnId, input, inputDigest: await turnInputDigest(input),
      genesisCheckpoint: await checkpoint(turnId), turnLeaseGeneration: state.nextTurnSequence + 1,
      leaseExpiresAt: 10_000,
      ...(publicly ? { publicAdmission: {
        authorizationGeneration: state.authorizationGeneration,
        idempotencyKeyDigest: await digestBytes(new TextEncoder().encode(`key:${turnId}`)),
        requestDigest: await digestBytes(new TextEncoder().encode(`request:${turnId}`)),
      } } : {}),
    };
  }
  async function complete() {
    return execute({
      kind: "commit_engine_step", commandId: `complete:${state.activeTurn!.turnId}`,
      expectedEventSequence: state.eventSequence, turnId: state.activeTurn!.turnId,
      transactionTime: 100, fence: fence(), consumedSettlementEffectId: state.activeTurn!.activeEffectId,
      effectIdentity: null, step: { kind: "turn_complete", checkpoint: await checkpoint(), result: { done: true } },
    });
  }
  async function effect(index: number) {
    const request = { service: "model" as const, operation: "complete", replayPolicy: "safe" as const, payload: { index } };
    const prepared = await execute({
      kind: "commit_engine_step", commandId: `prepare:${index}`, expectedEventSequence: state.eventSequence,
      turnId: state.activeTurn!.turnId, transactionTime: 100, fence: fence(),
      consumedSettlementEffectId: state.activeTurn!.activeEffectId,
      effectIdentity: { effectId: `effect:${index}`, invocationId: `invocation:${index}` },
      step: { kind: "effect_request", checkpoint: await checkpoint(), request: { ...request, requestDigest: await effectRequestDigest(request) } },
    });
    const activeEffect = prepared.state.effects.find((effect) => effect.effectId === `effect:${index}`)!;
    const common = {
      turnId: state.activeTurn!.turnId, effectId: activeEffect.effectId,
      invocationId: activeEffect.invocationId, requestDigest: activeEffect.requestDigest, fence: fence(),
    };
    await execute({
      ...common, kind: "dispatch_effect", commandId: `dispatch:${index}`, expectedEventSequence: state.eventSequence,
      transactionTime: 100, deadline: 500, providerRouteDigest: digest("4"),
    });
    return execute({
      ...common, kind: "settle_effect", commandId: `settle:${index}`, expectedEventSequence: state.eventSequence,
      dispatchAttempt: 1, settlement: { kind: "success", result: { index } },
    });
  }
  return { get state() { return state; }, archive, commands, execute, witness, admission, complete, effect };
}

describe("Bounded Session history aggregation", () => {
  it("archives terminal history while keeping exact command/admission replay and nonreuse", async () => {
    const f = fixture();
    for (let index = 0; index < 45; index += 1) {
      await f.execute(await f.admission(`turn:${index}`));
      await f.complete();
    }
    expect(f.state.history!.turnThrough).toBeGreaterThan(0);
    expect(f.state.commandReceipts.length).toBeLessThanOrEqual(SESSION_HISTORY_HOT_COMMANDS);
    expect(f.state.publicEvents.length).toBeLessThanOrEqual(SESSION_HISTORY_HOT_PUBLIC_EVENTS);
    expect(f.state.terminalTurns.length).toBeLessThanOrEqual(8);
    expect(f.archive.terminalTurns[0]?.turnId).toBe("turn:0");
    const before = f.state;
    const replay = await f.execute(f.commands[1]!);
    expect(replay).toMatchObject({ replayed: true, outcome: { kind: "engine_step_committed", status: "completed" } });
    expect(replay.state).toBe(before);
    expect(replay).not.toHaveProperty("archiveDelta");
    const original = f.commands[0]!;
    expect(original.kind).toBe("enqueue_turn");
    const admissionReplay = await f.execute({ ...original, commandId: "new-command-same-admission" });
    expect(admissionReplay).toMatchObject({ replayed: true, outcome: { turnId: "turn:0", turnSequence: 0 } });
    await expect(f.execute(await f.admission("turn:0", false))).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
    const duplicate = await f.admission("turn:0", false);
    await expect(f.execute({ ...duplicate, commandId: "duplicate-old-turn" })).rejects.toMatchObject({ code: "ALREADY_EXISTS" });
    const page = f.archive.publicEvents.filter((event) => event.sequence <= 16);
    expect(replaySessionPublicEvents(f.state, 0, 16, page).events.map((event) => event.sequence))
      .toEqual(Array.from({ length: 16 }, (_, index) => index + 1));
    expect(() => replaySessionPublicEvents(f.state, 0, 16)).toThrow(/authenticated/);
    await expect(validateSessionState(f.state)).resolves.toBeUndefined();
  });

  it("does not pin old public effects when only private plain turns follow", async () => {
    const f = fixture();
    await f.execute(await f.admission("effect-turn"));
    await f.effect(0);
    await f.complete();
    for (let index = 0; index < 40; index += 1) {
      await f.execute(await f.admission(`private:${index}`, false));
      await f.complete();
    }
    expect(f.archive.effects.map((effect) => effect.effectId)).toContain("effect:0");
    expect(f.archive.terminalTurns[0]?.turnId).toBe("effect-turn");
    expect(f.state.terminalTurns.length).toBeLessThanOrEqual(8);
    expect(f.state.history!.publicEventThrough).toBe(4);
    expect(f.state.history!.publicEventAnchors).toEqual([]);
    await expect(validateSessionState(f.state)).resolves.toBeUndefined();
  });

  it("compacts consumed effects during one active turn and fails closed without key-bound witnesses", async () => {
    const f = fixture();
    await f.execute(await f.admission("long-active"));
    for (let index = 0; index < 35; index += 1) await f.effect(index);
    expect(f.state.activeTurn?.turnId).toBe("long-active");
    expect(f.archive.effects.length).toBeGreaterThan(0);
    expect(f.state.effects.length).toBeLessThanOrEqual(9);
    expect(f.state.history!.publicEventAnchors.length).toBeLessThanOrEqual(1 + f.state.effects.length * 4);
    const oldSettlement = f.commands.find((command) => command.commandId === "settle:0")!;
    const replay = await f.execute(oldSettlement);
    expect(replay.replayed).toBe(true);
    expect(replay.outcome).toEqual(f.archive.commandReceipts.find((receipt) => receipt.commandId === "settle:0")!.outcome);
    await expect(applySessionCommand(f.state, oldSettlement, { transactionTime: 100 }))
      .rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
    const wrong = f.witness(oldSettlement);
    wrong.command!.commandId = "different-command";
    await expect(applySessionCommand(f.state, oldSettlement, { transactionTime: 100, history: wrong }))
      .rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
    await f.complete();
    await expect(validateSessionState(f.state)).resolves.toBeUndefined();
  });
});
