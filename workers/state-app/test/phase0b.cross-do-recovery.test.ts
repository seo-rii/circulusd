import type { Digest } from "@circulusd/protocol-types";
import { describe, expect, it } from "vitest";

import { replaySessionPublicEvents } from "../src/session/index.ts";
import { RecoverableWorkspaceEffect } from "./support/recoverable-workspace-effect.ts";

describe("Phase 0B reference-only cross-Durable-Object recovery", () => {
  it("recovers one committed workspace invocation into one gap-free Session settlement", async () => {
    const crashed = await RecoverableWorkspaceEffect.createCrashed();
    expect(crashed.evidence).toEqual({
      kind: "recoverable-workspace-effect-reference",
      referenceOnly: true,
      productionEligible: false,
      conformanceClaimed: false,
    });

    const beforeRecovery = await crashed.snapshot();
    expect(beforeRecovery.workspace).toMatchObject({
      eventSequence: 3,
      revision: 1,
      invocationLedger: [
        {
          invocationId: "phase0b-workspace-invocation",
          status: "committed",
          result: {
            workspaceCommitId: "phase0b-workspace-commit",
            revision: 1,
          },
        },
      ],
    });
    expect(beforeRecovery.workspace.revisions).toHaveLength(2);
    expect(beforeRecovery.workspace.invocationLedger[0]?.requestDigest).toBe(
      beforeRecovery.session.effects[0]?.requestDigest,
    );
    expect(beforeRecovery.session).toMatchObject({
      eventSequence: 3,
      publicEventSequence: 2,
      effects: [
        {
          service: "workspace",
          operation: "workspace.commit",
          phase: "dispatched",
          replayPolicy: "idempotency-key",
          invocationId: "phase0b-workspace-invocation",
          dispatchAttempt: 1,
          externalCommitId: null,
          settlement: null,
        },
      ],
    });
    expect(beforeRecovery.session.commandReceipts).toHaveLength(3);
    expect(crashed.diagnostics).toEqual({
      workspaceAcquireExecutions: 1,
      workspacePrepareExecutions: 1,
      workspaceCommitExecutions: 1,
      workspaceLedgerQueries: 0,
    });

    const firstWorker = crashed.restart();
    const secondWorker = crashed.restart();
    const recoveries = await Promise.all([
      firstWorker.recover(),
      secondWorker.recover(),
    ]);
    expect(
      recoveries.filter((result) => result.externalCommit.replayed === false),
    ).toHaveLength(1);
    expect(
      recoveries.filter((result) => result.externalCommit.replayed === true),
    ).toHaveLength(1);
    expect(
      recoveries.filter((result) => result.settlement.replayed === false),
    ).toHaveLength(1);
    expect(
      recoveries.filter((result) => result.settlement.replayed === true),
    ).toHaveLength(1);
    expect(recoveries.every((result) =>
      result.workspaceResult.workspaceCommitId === "phase0b-workspace-commit" &&
      result.workspaceResult.revision === 1
    )).toBe(true);

    const recovered = await crashed.restart().snapshot();
    expect(recovered.workspace).toMatchObject({
      eventSequence: 3,
      revision: 1,
    });
    expect(recovered.workspace.revisions).toHaveLength(2);
    expect(recovered.workspace.invocationLedger).toHaveLength(1);
    expect(recovered.session).toMatchObject({
      eventSequence: 5,
      publicEventSequence: 4,
      effects: [
        {
          phase: "settled",
          invocationId: "phase0b-workspace-invocation",
          externalCommitId: "phase0b-workspace-commit",
          settlement: {
            kind: "success",
            result: {
              workspaceCommitId: "phase0b-workspace-commit",
              revision: 1,
            },
          },
        },
      ],
    });
    expect(recovered.session.commandReceipts).toHaveLength(5);
    expect(
      recovered.session.commandReceipts.map((receipt) => receipt.committedEventSequence),
    ).toEqual([1, 2, 3, 4, 5]);
    expect(recovered.session.publicEvents.map((event) => event.sequence)).toEqual([
      1,
      2,
      3,
      4,
    ]);
    expect(recovered.session.publicEvents.map((event) => event.type)).toEqual([
      "turn.accepted",
      "tool.effect.prepared",
      "tool.externally_committed",
      "tool.settled",
    ]);
    expect(
      recovered.session.publicEvents
        .filter((event) => event.type.startsWith("tool."))
        .map((event) => ({ service: event.service, operation: event.operation })),
    ).toEqual([
      { service: "workspace", operation: "workspace.commit" },
      { service: "workspace", operation: "workspace.commit" },
      { service: "workspace", operation: "workspace.commit" },
    ]);
    expect(replaySessionPublicEvents(recovered.session, 0, 16)).toMatchObject({
      snapshot: { lastEventSequence: 4 },
      events: [
        { sequence: 1, type: "turn.accepted" },
        { sequence: 2, type: "tool.effect.prepared" },
        { sequence: 3, type: "tool.externally_committed" },
        { sequence: 4, type: "tool.settled" },
      ],
    });

    const repeated = await crashed.restart().recover();
    expect(repeated).toMatchObject({
      externalCommit: { replayed: true },
      settlement: { replayed: true },
      workspaceResult: {
        workspaceCommitId: "phase0b-workspace-commit",
        revision: 1,
      },
    });
    expect(crashed.diagnostics).toEqual({
      workspaceAcquireExecutions: 1,
      workspacePrepareExecutions: 1,
      workspaceCommitExecutions: 1,
      workspaceLedgerQueries: 3,
    });

    const mismatchedDigest = `sha256:${"f".repeat(64)}` as Digest;
    await expect(
      crashed.restart().recover({
        requestDigest: mismatchedDigest,
        authorityOverrides: { requestDigest: mismatchedDigest },
      }),
    ).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
    await expect(
      crashed.restart().recover({
        authorityOverrides: { sessionId: "different-session" },
      }),
    ).rejects.toMatchObject({ code: "STALE_GENERATION" });
    await expect(
      crashed.restart().recover({
        authorityOverrides: { dispatchAttempt: 2 },
      }),
    ).rejects.toMatchObject({ code: "STALE_GENERATION" });

    const afterRejectedRecovery = await crashed.restart().snapshot();
    expect(afterRejectedRecovery.workspace.revision).toBe(1);
    expect(afterRejectedRecovery.workspace.invocationLedger).toHaveLength(1);
    expect(afterRejectedRecovery.session.eventSequence).toBe(5);
    expect(afterRejectedRecovery.session.publicEventSequence).toBe(4);
    expect(crashed.diagnostics).toMatchObject({
      workspaceAcquireExecutions: 1,
      workspacePrepareExecutions: 1,
      workspaceCommitExecutions: 1,
      workspaceLedgerQueries: 6,
    });
  });
});
