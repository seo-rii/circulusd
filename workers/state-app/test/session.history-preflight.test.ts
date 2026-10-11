import { PROTOCOL_MAJOR, PROTOCOL_MINOR, PROTOCOL_NAME, type Digest } from "@circulusd/protocol-types";
import { expect, it } from "vitest";

import { SessionCell, sessionCellName } from "../src/host/index.ts";
import type { TransactionalStoragePort, TransactionPort } from "../src/host/contracts.ts";
import { HOST_RPC_CONTRACTS, type HostRpcOperation, type HostRpcResponse } from "../src/host/rpc.ts";
import { SESSION_HISTORY_HOT_COMMANDS } from "../src/session/index.ts";
import { RestartableDurableStorage } from "./support/restartable-durable-storage.ts";

it("rejects malformed lookup inputs before archive I/O and leaves durable state unchanged", async () => {
  const backing = new RestartableDurableStorage();
  const reads: string[] = [];
  const writes: string[] = [];
  const storage: TransactionalStoragePort = {
    transaction: <Result>(callback: (transaction: TransactionPort) => Promise<Result>) => backing.transaction((transaction) => callback({
      get: <Value>(key: string) => { reads.push(key); return transaction.get<Value>(key); },
      put: async (key, value) => { writes.push(key); await transaction.put(key, value); },
      delete: async (key) => { writes.push(key); return transaction.delete(key); },
    })),
  };
  const id = (name: string) => ({ toString: () => name, equals: (other: unknown) => String(other) === name });
  const cell = new SessionCell(
    { storage, id: id(sessionCellName("tenant", "session")) } as never,
    { SESSION_CELL: { idFromName: id } } as never,
    () => 100,
  );
  const digest = (value: string): Digest => `sha256:${value.repeat(64)}`;
  const request = (operation: HostRpcOperation, payload: unknown) => ({
    protocol: PROTOCOL_NAME, major: PROTOCOL_MAJOR, minor: PROTOCOL_MINOR,
    schemaDigest: HOST_RPC_CONTRACTS[operation].schemaDigest,
    requestId: "history-preflight", payload,
  });
  const initialize = await cell.initializeSession(request("session.initialize", {
    sessionId: "session", tenantId: "tenant", userId: "user", workspaceId: "workspace",
    runtimeRevisionDigest: digest("1"), policySnapshotDigest: digest("2"), emergencyOverlayDigest: digest("3"),
    engineKind: "low-level", adapterAbiVersion: 1, checkpointSchemaVersion: 1,
    placementGeneration: 1, sandboxGeneration: 1, authorizationGeneration: 1,
  }));
  expect(initialize.payload.ok).toBe(true);
  const total = SESSION_HISTORY_HOT_COMMANDS + 2;
  const rotation = (sequence: number) => ({
    kind: "rotate_generations", commandId: `rotate-${sequence}`, expectedEventSequence: sequence,
    nextPlacementGeneration: sequence + 2, nextSandboxGeneration: 1,
    nextAuthorizationGeneration: 1, nextEmergencyOverlayDigest: digest("3"),
  });
  for (let sequence = 0; sequence < total; sequence += 1) {
    const response = await cell.executeSessionCommand(request("session.execute", rotation(sequence)));
    expect(response.payload.ok).toBe(true);
  }
  expect(writes.some((key) => key.startsWith("circulusd.state-app.session-history.v1."))).toBe(true);
  const missingIdentity = {
    kind: "commit_engine_step", commandId: "missing-effect-identity", expectedEventSequence: total,
    turnId: "turn", fence: { turnLeaseGeneration: 1, placementGeneration: total + 1, sandboxGeneration: 1, authorizationGeneration: 1 },
    transactionTime: 100, consumedSettlementEffectId: null, step: {},
  };
  const cases = [
    missingIdentity,
    ...[42, "", "x".repeat(4097), "é".repeat(129), "bad\nkey"].map((commandId) => ({ ...rotation(total), commandId })),
    { ...rotation(total), expectedEventSequence: -1 },
  ];
  const revision = backing.durableRevision;
  for (const [index, command] of cases.entries()) {
    reads.length = 0;
    writes.length = 0;
    const response: HostRpcResponse<unknown> = await cell.executeSessionCommand(request("session.execute", command));
    expect(response.payload, `malformed command case ${index}`).toMatchObject({ ok: false, error: { code: "INVALID_ARGUMENT" } });
    expect(reads.filter((key) => key.startsWith("circulusd.state-app.session-history.v1."))).toEqual([]);
    expect(writes).toEqual([]);
    expect(backing.durableRevision).toBe(revision);
  }
  // RPC normalization intentionally canonicalizes payload strings before the
  // aggregate runs. Preserve that existing behavior and its replay digest.
  const normalized = await cell.executeSessionCommand(request("session.execute", { ...rotation(total), commandId: "e\u0301" }));
  expect(normalized.payload.ok).toBe(true);
  const replay = await cell.executeSessionCommand(request("session.execute", { ...rotation(total), commandId: "é" }));
  expect(replay.payload).toMatchObject({ ok: true, result: { replayed: true } });
  expect(backing.durableRevision).toBe(revision + 1);
});
