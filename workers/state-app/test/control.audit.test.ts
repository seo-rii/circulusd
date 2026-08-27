import { describe, expect, it } from "vitest";

import {
  AUDIT_GENESIS_HASH,
  applyAuditCommand,
  createAuditState,
  readAuditEntries,
  validateAuditState,
  type AuditAggregateState,
  type AuditEventInput,
  type ControlAuthoritySnapshot,
} from "../src/control/index.ts";
import { AUDIT_STATE_MAX_BYTES } from "../src/control/validation.ts";

function authority(
  overrides: Partial<ControlAuthoritySnapshot> = {},
): ControlAuthoritySnapshot {
  return {
    serviceBinding: "state",
    tenantId: "tenant-1",
    actorUserId: "admin-1",
    subjectKind: "tenant",
    subjectId: "tenant-1",
    roles: ["tenant-admin"],
    permissions: ["audit.append", "audit.read"],
    authorizationGeneration: 3,
    currentAuthorizationGeneration: 3,
    issuedAt: 1,
    expiresAt: 10_000,
    ...overrides,
  };
}

function event(overrides: Partial<AuditEventInput> = {}): AuditEventInput {
  return {
    timestamp: 100,
    actorUserId: "admin-1",
    eventType: "generation.rotation",
    result: "success",
    correlation: {
      userId: "user-1",
      sessionId: null,
      turnId: null,
      effectId: null,
      runtimeRevision: null,
      workspaceId: "workspace-1",
      agentShardId: null,
      placementGeneration: null,
      executionBackend: null,
      executionEnvironmentRevision: null,
      sandboxId: null,
      sandboxGeneration: null,
      invocationId: "rotation-1",
    },
    metadata: { generationKind: "workspace-security", from: 7, to: 8 },
    ...overrides,
  };
}

function state(): AuditAggregateState {
  return createAuditState({ tenantId: "tenant-1" });
}

describe("Audit aggregate", () => {
  it("leaves host routing headroom inside the 4 MiB isolate-safe record cap", () => {
    expect(AUDIT_STATE_MAX_BYTES).toBe(3 * 1_048_576);
  });

  it("paginates reads only after tenant-level audit ACL validation", async () => {
    const committed = await applyAuditCommand(state(), {
      kind: "append_audit_event",
      commandId: "audit-read-1",
      expectedSequence: 0,
      now: 100,
      authority: authority(),
      event: event(),
    });
    const entries = await readAuditEntries(
      committed.state,
      0,
      10,
      authority({ permissions: ["audit.read"] }),
      101,
    );
    expect(entries).toEqual(committed.state.entries);
    expect(entries).not.toBe(committed.state.entries);
    await expect(
      readAuditEntries(
        committed.state,
        0,
        10,
        authority({ tenantId: "tenant-2", subjectId: "tenant-2", permissions: ["audit.read"] }),
        101,
      ),
    ).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
  });

  it("appends a monotonic, replay-safe hash chain without mutating prior state", async () => {
    const initial = state();
    const firstCommand = {
      kind: "append_audit_event" as const,
      commandId: "audit-1",
      expectedSequence: 0,
      now: 100,
      authority: authority(),
      event: event(),
    };
    const first = await applyAuditCommand(initial, firstCommand);
    expect(initial.entries).toEqual([]);
    expect(first.state.sequence).toBe(1);
    expect(first.state.entries[0]?.previousHash).toBe(AUDIT_GENESIS_HASH);
    expect(first.state.entries[0]?.hash).toBe(first.state.headHash);

    const second = await applyAuditCommand(first.state, {
      kind: "append_audit_event",
      commandId: "audit-2",
      expectedSequence: 1,
      now: 110,
      authority: authority(),
      event: event({ timestamp: 110, eventType: "runtime.activate" }),
    });
    expect(second.state.sequence).toBe(2);
    expect(second.state.entries[1]?.previousHash).toBe(first.state.headHash);
    await expect(validateAuditState(second.state)).resolves.toBeUndefined();

    const replay = await applyAuditCommand(second.state, {
      ...firstCommand,
      now: 120,
      authority: authority({
        authorizationGeneration: 4,
        currentAuthorizationGeneration: 4,
        issuedAt: 115,
        expiresAt: 20_000,
      }),
    });
    expect(replay.replayed).toBe(true);
    expect(replay.state).toBe(second.state);
    expect(replay.outcome.sequence).toBe(1);
  });

  it("detects entry modification, removal, reordering, and head substitution", async () => {
    const first = await applyAuditCommand(state(), {
      kind: "append_audit_event",
      commandId: "audit-1",
      expectedSequence: 0,
      now: 100,
      authority: authority(),
      event: event(),
    });
    const second = await applyAuditCommand(first.state, {
      kind: "append_audit_event",
      commandId: "audit-2",
      expectedSequence: 1,
      now: 101,
      authority: authority(),
      event: event({ timestamp: 101, eventType: "policy.change" }),
    });

    const modified = structuredClone(second.state);
    modified.entries[0]!.event.result = "failure";
    await expect(validateAuditState(modified)).rejects.toMatchObject({
      code: "FAILED_PRECONDITION",
    });

    const removed = structuredClone(second.state);
    removed.entries.shift();
    await expect(validateAuditState(removed)).rejects.toMatchObject({
      code: "FAILED_PRECONDITION",
    });

    const reordered = structuredClone(second.state);
    reordered.entries.reverse();
    await expect(validateAuditState(reordered)).rejects.toMatchObject({
      code: "FAILED_PRECONDITION",
    });

    const changedHead = structuredClone(second.state);
    changedHead.headHash = AUDIT_GENESIS_HASH;
    await expect(validateAuditState(changedHead)).rejects.toMatchObject({
      code: "FAILED_PRECONDITION",
    });

    const transplantedTenant = structuredClone(second.state);
    transplantedTenant.tenantId = "tenant-2";
    await expect(validateAuditState(transplantedTenant)).rejects.toMatchObject({
      code: "FAILED_PRECONDITION",
    });
  });

  it("binds each receipt command identity and digest into the audit chain", async () => {
    const committed = await applyAuditCommand(state(), {
      kind: "append_audit_event",
      commandId: "audit-1",
      expectedSequence: 0,
      now: 100,
      authority: authority(),
      event: event(),
    });

    const relabeled = structuredClone(committed.state);
    relabeled.commandReceipts[0]!.commandId = "audit-relabeled";
    await expect(validateAuditState(relabeled)).rejects.toMatchObject({
      code: "FAILED_PRECONDITION",
    });

    const digestSubstituted = structuredClone(committed.state);
    digestSubstituted.commandReceipts[0]!.commandDigest = `sha256:${"f".repeat(64)}`;
    await expect(validateAuditState(digestSubstituted)).rejects.toMatchObject({
      code: "FAILED_PRECONDITION",
    });
  });

  it("enforces tenant ACL, event exact shape, timestamp order, and metadata hygiene", async () => {
    const initial = state();
    const base = {
      kind: "append_audit_event" as const,
      commandId: "audit-1",
      expectedSequence: 0,
      now: 100,
      authority: authority(),
      event: event(),
    };
    await expect(
      applyAuditCommand(initial, {
        ...base,
        authority: authority({ tenantId: "tenant-2", subjectId: "tenant-2" }),
      }),
    ).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    await expect(
      applyAuditCommand(initial, {
        ...base,
        authority: authority({ permissions: ["audit.read"] }),
      }),
    ).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    await expect(
      applyAuditCommand(initial, {
        ...base,
        event: { ...event(), unexpected: true } as never,
      }),
    ).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
    await expect(
      applyAuditCommand(initial, {
        ...base,
        event: event({ metadata: { rawSecret: "do-not-log" } }),
      }),
    ).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });

    const first = await applyAuditCommand(initial, base);
    await expect(
      applyAuditCommand(first.state, {
        ...base,
        commandId: "audit-2",
        expectedSequence: 1,
        now: 101,
        event: event({ timestamp: 99 }),
      }),
    ).rejects.toMatchObject({ code: "FAILED_PRECONDITION" });
  });

  it("rejects sequence races, idempotency conflicts, and oversized events", async () => {
    const initial = state();
    const base = {
      kind: "append_audit_event" as const,
      commandId: "audit-1",
      expectedSequence: 0,
      now: 100,
      authority: authority(),
      event: event(),
    };
    const winner = await applyAuditCommand(initial, base);
    await expect(
      applyAuditCommand(winner.state, {
        ...base,
        commandId: "audit-2",
      }),
    ).rejects.toMatchObject({ code: "CONFLICT" });
    await expect(
      applyAuditCommand(winner.state, {
        ...base,
        event: event({ eventType: "different" }),
      }),
    ).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
    await expect(
      applyAuditCommand(initial, {
        ...base,
        event: event({ metadata: { huge: "x".repeat(100_000) } }),
      }),
    ).rejects.toMatchObject({ code: "RESOURCE_EXHAUSTED" });
  });
});
