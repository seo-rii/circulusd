import { describe, expect, it } from "vitest";
import { digestBytes, encodeCanonicalCbor, type Digest } from "@circulusd/protocol-types";
import type { AggregateAdapter, AggregateApplyContext, AggregateApplyResult, TransactionPort } from "../src/host/contracts.ts";
import { TransactionalAggregateKernel, type AggregateTransactionCompanion } from "../src/host/kernel.ts";
import { emptySessionHistoryIndexRoot, type SessionHistoryIndexRoot } from "../src/host/session-history-index.ts";
import { SessionHistoryStore, readArchivedSessionBlobReference } from "../src/host/session-history-store.ts";
import { ChunkedAggregateStorage } from "../src/host/storage.ts";
import { createSessionState } from "../src/session/aggregate.ts";
import type { SessionArchiveDelta, SessionAggregateState, SessionPublicEvent } from "../src/session/types.ts";
import { RestartableDurableStorage } from "./support/restartable-durable-storage.ts";

const digest = (character: string): Digest => `sha256:${character.repeat(64)}`;
const createState = () => createSessionState({
  sessionId: "session-history", tenantId: "tenant-history", userId: "user-history",
  workspaceId: "workspace-history", runtimeRevisionDigest: digest("1"),
  policySnapshotDigest: digest("2"), emergencyOverlayDigest: digest("3"),
  engineKind: "low-level", adapterAbiVersion: 1, checkpointSchemaVersion: 1,
  placementGeneration: 4, sandboxGeneration: 5, authorizationGeneration: 6,
});
const emptyDelta = (): SessionArchiveDelta => ({
  commandReceipts: [], publicEvents: [], terminalTurns: [], effects: [], turnAdmissionReceipts: [], turnIdentities: [],
});
const event = (sequence: number): SessionPublicEvent => ({
  sequence, type: "turn.accepted", turnId: `turn-${sequence}`, turnSequence: sequence - 1, status: "active",
});
function withThrough(state: SessionAggregateState, publicEventThrough: number): SessionAggregateState {
  return { ...state, publicEventSequence: publicEventThrough, history: {
    commandThrough: 0, publicEventThrough, turnThrough: 0,
    runtimePointerAtCommandThrough: state.runtimePointer, latestSettledTurnAtTurnThrough: null,
    publicEventAnchors: [], dispatchStartReceipts: [], runtimeRevisionDigests: [],
  } };
}

describe("Session archive storage", () => {
  it("persists a newly created payload owned only by history in the same transaction", async () => {
    const storage = new RestartableDurableStorage();
    const state = createState();
    const records = new ChunkedAggregateStorage<SessionAggregateState>("session", () => {});
    const bytes = encodeCanonicalCbor({ newlyArchived: 42 });
    const payloadDigest = await digestBytes(bytes);
    const blobs = new Map([[payloadDigest, bytes]]);
    const delta = emptyDelta();
    delta.commandReceipts.push({ commandId: "newly-archived", commandDigest: digest("4"), committedEventSequence: 1,
      outcome: { kind: "effect_settled", effectId: "new-effect", settlement: {
        kind: "success", resultPayloadRef: { encoding: "canonical-cbor-v1", digest: payloadDigest,
          encodedBytes: bytes.length, encodedItems: 3 },
      } } });
    await storage.transaction(async (transaction) => {
      const store = new SessionHistoryStore(transaction);
      await store.archive(delta, state, [], blobs);
      await store.flush();
      await records.write(transaction, records.buildInitialRecord(digest("5"), state), undefined, blobs, [], store.root());
      expect(await records.readBlob(transaction, payloadDigest)).toEqual(bytes);
    });
    await storage.restart().transaction(async (transaction) => {
      const stored = (await records.read(transaction))!;
      expect(stored.manifest.referencedBlobs).toEqual([]);
      expect(stored.manifest.sessionHistory?.size).toBe(3);
      expect(await records.readBlob(transaction, payloadDigest)).toEqual(bytes);
    });
  });

  it("replaces partial event pages atomically without retaining unreachable rows", async () => {
    const storage = new RestartableDurableStorage();
    const state = createState();
    const append = (start: number, end: number) => storage.transaction(async (transaction) => {
      const root = await transaction.get<SessionHistoryIndexRoot>("history-root");
      const previous = start === 1 ? state : withThrough(state, start - 1);
      const store = new SessionHistoryStore(transaction, root, previous);
      const delta = emptyDelta();
      delta.publicEvents = Array.from({ length: end - start + 1 }, (_, i) => event(start + i));
      await store.archive(delta, previous, []);
      await store.flush();
      await transaction.put("history-root", store.root());
    });
    await append(1, 1);
    expect(storage.durableEntryCount).toBe(4); // root, index, row header and row chunk.
    for (let sequence = 2; sequence <= 16; sequence += 1) await append(sequence, sequence);
    expect(storage.durableEntryCount).toBe(4);
    await append(17, 20);
    expect(storage.durableEntryCount).toBe(6);
    await storage.restart().transaction(async (transaction) => {
      const store = new SessionHistoryStore(transaction, await transaction.get("history-root"), withThrough(state, 20));
      expect((await store.events(withThrough(state, 20), 14, 5)).map(({ sequence }) => sequence)).toEqual([15, 16, 17, 18, 19]);
    });
    const revision = storage.durableRevision;
    const count = storage.durableEntryCount;
    storage.injectCrashOnce("before-commit");
    await expect(append(21, 22)).rejects.toMatchObject({ phase: "before-commit" });
    expect(storage.durableRevision).toBe(revision);
    expect(storage.durableEntryCount).toBe(count);
    storage.injectCrashOnce("after-commit-before-result");
    await expect(append(21, 22)).rejects.toMatchObject({ phase: "after-commit-before-result" });
    await storage.restart().transaction(async (transaction) => {
      const store = new SessionHistoryStore(transaction, await transaction.get("history-root"), withThrough(state, 22));
      expect((await store.events(withThrough(state, 22), 19, 4)).map(({ sequence }) => sequence)).toEqual([20, 21, 22]);
    });
  });

  it("pins shared payloads once and rejects conflicting immutable receipt identities", async () => {
    const storage = new RestartableDurableStorage();
    const state = createState();
    const bytes = encodeCanonicalCbor({ result: "shared" });
    const payloadDigest = await digestBytes(bytes);
    const ref = { digest: payloadDigest, encodedBytes: bytes.length };
    const delta = emptyDelta();
    delta.commandReceipts = [1, 2].map((sequence) => ({
      commandId: `command-${sequence}`, commandDigest: digest("4"), committedEventSequence: sequence,
      outcome: { kind: "effect_settled", effectId: `effect-${sequence}`, settlement: {
        kind: "success", resultPayloadRef: { encoding: "canonical-cbor-v1", ...ref, encodedItems: 3 },
      } },
    }));
    await storage.transaction(async (transaction) => {
      const store = new SessionHistoryStore(transaction);
      await store.archive(delta, state, [ref]);
      await store.flush();
      await transaction.put("history-root", store.root());
    });
    await storage.transaction(async (transaction) => {
      const root = (await transaction.get<SessionHistoryIndexRoot>("history-root"))!;
      expect(root.size).toBe(5); // Two command/sequence aliases and one shared pin.
      expect(await readArchivedSessionBlobReference(transaction, root, payloadDigest)).toEqual(ref);
      expect(await readArchivedSessionBlobReference(transaction, root, digest("9"))).toBeNull();
    });
    const revision = storage.durableRevision;
    await expect(storage.transaction(async (transaction) => {
      const store = new SessionHistoryStore(transaction, await transaction.get("history-root"));
      const conflict = structuredClone(delta);
      conflict.commandReceipts[0]!.commandDigest = digest("5");
      await store.archive(conflict, state, [ref]);
      await store.flush();
    })).rejects.toMatchObject({ code: "CORRUPT_STATE" });
    expect(storage.durableRevision).toBe(revision);
  });
});

interface TestState { version: number; schema: number }
interface TestContext extends AggregateApplyContext { count: number }
type TestApplied = AggregateApplyResult<TestState, number>;
function budgetFixture(count: number, adaptive: boolean, migrate: boolean) {
  const storage = new RestartableDurableStorage();
  const attempts: number[] = [];
  const mutationSets: Set<string>[] = [];
  const observed = { transaction: <Value>(callback: (transaction: TransactionPort) => Promise<Value>) => storage.transaction(async (transaction) => {
    const keys = new Set<string>(); mutationSets.push(keys);
    return callback({
      get: transaction.get,
      put: async (key, value) => { keys.add(key); await transaction.put(key, value); },
      delete: async (key) => { keys.add(key); return transaction.delete(key); },
    });
  }) };
  const adapter: AggregateAdapter<TestState, null, null, number, number, TestContext, TestApplied> = {
    kind: "session", create: () => ({ version: 0, schema: 1 }),
    validate: () => {}, version: (state) => state.version,
    apply: async (state, _command, context) => {
      attempts.push(context.count);
      return { state: { ...state, version: state.version + 1 }, outcome: context.count, replayed: false };
    },
  };
  const companion: AggregateTransactionCompanion<TestState, null, number, TestContext, TestApplied> = {
    prepareContext: async (_transaction, _stored, _command, context) => ({ ...context, count }),
    persist: async (transaction, _stored, _command, applied) => {
      for (let i = 0; i < applied.outcome; i += 1) await transaction.put(`archive-budget-${i}`, i);
      return emptySessionHistoryIndexRoot();
    },
    ...(adaptive ? { reduceArchiveBatch: (context: TestContext) => context.count <= 1 ? undefined
      : { ...context, count: Math.floor(context.count / 2) } } : {}),
  };
  const initial = new TransactionalAggregateKernel({ storage: observed }, adapter);
  const currentAdapter: typeof adapter = migrate ? { ...adapter, migrate: (value) => {
    const state = value as TestState;
    return { state: { ...state, schema: 2 }, migrated: state.schema !== 2 };
  } } : adapter;
  const kernel = new TransactionalAggregateKernel({ storage: observed }, currentAdapter, undefined, () => 1, companion);
  return { storage, attempts, mutationSets, initial, kernel };
}

describe("planned archive transaction budget", () => {
  it.each([128, 129])("counts migration plus archive/index/state as %i exact keys before flushing", async (keys) => {
    const f = budgetFixture(keys - 4, false, true);
    await f.initial.initialize(null);
    const revision = f.storage.durableRevision;
    const entries = f.storage.durableEntryCount;
    if (keys === 128) {
      expect(await f.kernel.execute(null)).toMatchObject({ version: 1, outcome: 124 });
      expect(f.mutationSets.at(-1)?.size).toBe(128);
    } else {
      await expect(f.kernel.execute(null)).rejects.toMatchObject({ code: "INVALID_AGGREGATE_OUTPUT" });
      expect(f.storage.durableRevision).toBe(revision);
      expect(f.storage.durableEntryCount).toBe(entries);
      expect(await f.initial.query(null, (state) => state)).toEqual({ version: 0, schema: 1 });
    }
  });

  it("discards an oversized proposal and recomputes a smaller archive before any archive write", async () => {
    const f = budgetFixture(126, true, false);
    await f.initial.initialize(null);
    expect(await f.kernel.execute(null)).toMatchObject({ version: 1, outcome: 63 });
    expect(f.attempts).toEqual([126, 63]);
    expect(f.mutationSets.at(-1)?.size).toBe(66);
    await f.storage.transaction(async (transaction) => {
      expect(await transaction.get("archive-budget-62")).toBe(62);
      expect(await transaction.get("archive-budget-63")).toBeUndefined();
    });
  });
});
