import { digestBytes, type Digest } from "@circulusd/protocol-types";
import { describe, expect, it } from "vitest";

import {
  applySessionCommand,
  assertSessionInvariants,
  createSessionState,
  turnInputDigest,
  type SessionAggregateState,
} from "../src/session/index.ts";

const ACTIVE = `sha256:${"1".repeat(64)}` as Digest;
const CANDIDATE = `sha256:${"2".repeat(64)}` as Digest;
const SECOND_CANDIDATE = `sha256:${"3".repeat(64)}` as Digest;
const POLICY = `sha256:${"4".repeat(64)}` as Digest;
const EMERGENCY = `sha256:${"5".repeat(64)}` as Digest;
const HEALTH_RECEIPT = `sha256:${"6".repeat(64)}` as Digest;
const MIGRATION_RECEIPT = `sha256:${"7".repeat(64)}` as Digest;
const FAILURE_RECEIPT = `sha256:${"8".repeat(64)}` as Digest;

function newSession(): SessionAggregateState {
  return createSessionState({
    sessionId: "sess_runtime",
    tenantId: "tenant_runtime",
    userId: "user_runtime",
    workspaceId: "workspace_runtime",
    runtimeRevisionDigest: ACTIVE,
    policySnapshotDigest: POLICY,
    emergencyOverlayDigest: EMERGENCY,
    engineKind: "low-level",
    adapterAbiVersion: 1,
    checkpointSchemaVersion: 1,
    placementGeneration: 4,
    sandboxGeneration: 5,
    authorizationGeneration: 6,
  });
}

describe("Session staged runtime revision pointer", () => {
  it("starts with an immutable active pointer and no candidate or rollback target", () => {
    const state = newSession();

    expect(state.runtimePointer).toEqual({
      activeRevision: ACTIVE,
      candidateRevision: null,
      previousRevision: null,
      switchGeneration: 1,
    });
    expect(state.runtimeRevisionDigest).toBe(state.runtimePointer.activeRevision);
  });

  it("stages, activates with health and migration evidence, and replays idempotently", async () => {
    const staged = await applySessionCommand(newSession(), {
      kind: "stage_runtime_revision",
      commandId: "stage_runtime_candidate",
      expectedEventSequence: 0,
      candidateRevision: CANDIDATE,
    });
    expect(staged.state.runtimePointer).toEqual({
      activeRevision: ACTIVE,
      candidateRevision: CANDIDATE,
      previousRevision: null,
      switchGeneration: 1,
    });

    const command = {
      kind: "activate_runtime_revision" as const,
      commandId: "activate_runtime_candidate",
      expectedEventSequence: staged.state.eventSequence,
      expectedActiveRevision: ACTIVE,
      expectedCandidateRevision: CANDIDATE,
      expectedSwitchGeneration: 1,
      healthReceiptDigest: HEALTH_RECEIPT,
      migrationReceiptDigest: MIGRATION_RECEIPT,
    };
    const activated = await applySessionCommand(staged.state, command);

    expect(activated.state.runtimeRevisionDigest).toBe(CANDIDATE);
    expect(activated.state.runtimePointer).toEqual({
      activeRevision: CANDIDATE,
      candidateRevision: null,
      previousRevision: ACTIVE,
      switchGeneration: 2,
    });
    expect(activated.outcome).toEqual({
      kind: "runtime_revision_activated",
      activeRevision: CANDIDATE,
      previousRevision: ACTIVE,
      switchGeneration: 2,
      healthReceiptDigest: HEALTH_RECEIPT,
      migrationReceiptDigest: MIGRATION_RECEIPT,
    });

    const replay = await applySessionCommand(activated.state, command);
    expect(replay.replayed).toBe(true);
    expect(replay.state).toBe(activated.state);
    expect(replay.outcome).toEqual(activated.outcome);
  });

  it("keeps the active revision when candidate health or migration fails", async () => {
    const staged = await applySessionCommand(newSession(), {
      kind: "stage_runtime_revision",
      commandId: "stage_failed_candidate",
      expectedEventSequence: 0,
      candidateRevision: CANDIDATE,
    });
    const discarded = await applySessionCommand(staged.state, {
      kind: "discard_runtime_candidate",
      commandId: "discard_failed_candidate",
      expectedEventSequence: staged.state.eventSequence,
      expectedCandidateRevision: CANDIDATE,
      failureReceiptDigest: FAILURE_RECEIPT,
    });

    expect(discarded.state.runtimeRevisionDigest).toBe(ACTIVE);
    expect(discarded.state.runtimePointer).toEqual({
      activeRevision: ACTIVE,
      candidateRevision: null,
      previousRevision: null,
      switchGeneration: 1,
    });
  });

  it("rejects stale competing candidates and stale activation CAS inputs", async () => {
    const staged = await applySessionCommand(newSession(), {
      kind: "stage_runtime_revision",
      commandId: "stage_first_candidate",
      expectedEventSequence: 0,
      candidateRevision: CANDIDATE,
    });

    await expect(
      applySessionCommand(staged.state, {
        kind: "stage_runtime_revision",
        commandId: "stage_second_candidate",
        expectedEventSequence: staged.state.eventSequence,
        candidateRevision: SECOND_CANDIDATE,
      }),
    ).rejects.toMatchObject({ code: "CONFLICT" });
    await expect(
      applySessionCommand(staged.state, {
        kind: "activate_runtime_revision",
        commandId: "activate_stale_generation",
        expectedEventSequence: staged.state.eventSequence,
        expectedActiveRevision: ACTIVE,
        expectedCandidateRevision: CANDIDATE,
        expectedSwitchGeneration: 2,
        healthReceiptDigest: HEALTH_RECEIPT,
        migrationReceiptDigest: MIGRATION_RECEIPT,
      }),
    ).rejects.toMatchObject({ code: "CONFLICT" });
  });

  it("drains active work and freezes new turn admission before activation", async () => {
    const state = newSession();
    const input = { message: "finish on the old runtime" };
    const payloadBytes = new TextEncoder().encode("runtime-drain-genesis");
    const admitted = await applySessionCommand(state, {
      kind: "enqueue_turn",
      commandId: "enqueue_before_staging",
      expectedEventSequence: 0,
      transactionTime: 1_700_000_000_000,
      turnId: "turn_runtime_drain",
      input,
      inputDigest: await turnInputDigest(input),
      genesisCheckpoint: {
        kind: "genesis",
        engineKind: state.engineKind,
        adapterAbiVersion: state.adapterAbiVersion,
        checkpointSchemaVersion: state.checkpointSchemaVersion,
        runtimeRevisionDigest: state.runtimeRevisionDigest,
        sessionId: state.sessionId,
        turnId: "turn_runtime_drain",
        checkpointSequence: 0,
        predecessorDigest: null,
        payloadEncoding: "opaque-v1",
        payloadBytes,
        payloadDigest: await digestBytes(payloadBytes),
      },
      turnLeaseGeneration: 1,
      leaseExpiresAt: 1_800_000_000_000,
    });
    const staged = await applySessionCommand(admitted.state, {
      kind: "stage_runtime_revision",
      commandId: "stage_while_old_turn_runs",
      expectedEventSequence: admitted.state.eventSequence,
      candidateRevision: CANDIDATE,
    });

    await expect(
      applySessionCommand(staged.state, {
        kind: "activate_runtime_revision",
        commandId: "activate_before_drain",
        expectedEventSequence: staged.state.eventSequence,
        expectedActiveRevision: ACTIVE,
        expectedCandidateRevision: CANDIDATE,
        expectedSwitchGeneration: 1,
        healthReceiptDigest: HEALTH_RECEIPT,
        migrationReceiptDigest: MIGRATION_RECEIPT,
      }),
    ).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });

    const secondInput = { message: "must wait for activation" };
    await expect(
      applySessionCommand(staged.state, {
        kind: "enqueue_turn",
        commandId: "enqueue_during_staging",
        expectedEventSequence: staged.state.eventSequence,
        transactionTime: 1_700_000_000_001,
        turnId: "turn_runtime_blocked",
        input: secondInput,
        inputDigest: await turnInputDigest(secondInput),
        genesisCheckpoint: {
          kind: "genesis",
          engineKind: staged.state.engineKind,
          adapterAbiVersion: staged.state.adapterAbiVersion,
          checkpointSchemaVersion: staged.state.checkpointSchemaVersion,
          runtimeRevisionDigest: staged.state.runtimeRevisionDigest,
          sessionId: staged.state.sessionId,
          turnId: "turn_runtime_blocked",
          checkpointSequence: 0,
          predecessorDigest: null,
          payloadEncoding: "opaque-v1",
          payloadBytes,
          payloadDigest: await digestBytes(payloadBytes),
        },
        turnLeaseGeneration: 2,
        leaseExpiresAt: 1_800_000_000_000,
      }),
    ).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
  });

  it("rolls back only the next-turn runtime pointer through a fenced CAS", async () => {
    const staged = await applySessionCommand(newSession(), {
      kind: "stage_runtime_revision",
      commandId: "stage_for_rollback",
      expectedEventSequence: 0,
      candidateRevision: CANDIDATE,
    });
    const activated = await applySessionCommand(staged.state, {
      kind: "activate_runtime_revision",
      commandId: "activate_for_rollback",
      expectedEventSequence: staged.state.eventSequence,
      expectedActiveRevision: ACTIVE,
      expectedCandidateRevision: CANDIDATE,
      expectedSwitchGeneration: 1,
      healthReceiptDigest: HEALTH_RECEIPT,
      migrationReceiptDigest: MIGRATION_RECEIPT,
    });
    const rolledBack = await applySessionCommand(activated.state, {
      kind: "rollback_runtime_revision",
      commandId: "rollback_failed_runtime",
      expectedEventSequence: activated.state.eventSequence,
      expectedActiveRevision: CANDIDATE,
      expectedPreviousRevision: ACTIVE,
      expectedSwitchGeneration: 2,
      failureReceiptDigest: FAILURE_RECEIPT,
    });

    expect(rolledBack.state.runtimeRevisionDigest).toBe(ACTIVE);
    expect(rolledBack.state.runtimePointer).toEqual({
      activeRevision: ACTIVE,
      candidateRevision: null,
      previousRevision: CANDIDATE,
      switchGeneration: 3,
    });
  });

  it("rejects corrupted or aliased active runtime pointers", () => {
    const mismatched = structuredClone(newSession());
    mismatched.runtimePointer.activeRevision = CANDIDATE;
    expect(() => assertSessionInvariants(mismatched)).toThrowError(
      expect.objectContaining({ code: "FAILED_PRECONDITION" }),
    );

    const aliased = structuredClone(newSession());
    aliased.runtimePointer.candidateRevision = ACTIVE;
    expect(() => assertSessionInvariants(aliased)).toThrowError(
      expect.objectContaining({ code: "FAILED_PRECONDITION" }),
    );
  });
});
