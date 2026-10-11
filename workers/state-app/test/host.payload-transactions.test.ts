import { describe, expect, it } from "vitest";

import {
  decodeCanonicalCbor,
  digestBytes,
  encodeCanonicalCbor,
  type Digest,
} from "@circulusd/protocol-types";

import {
  HostContractError,
  type AggregateAdapter,
  type TransactionalStoragePort,
  type TransactionPort,
} from "../src/host/contracts.ts";
import { TransactionalAggregateKernel } from "../src/host/kernel.ts";
import { RestartableDurableStorage } from "./support/restartable-durable-storage.ts";

class ObservedStorage implements TransactionalStoragePort {
  readonly backing = new RestartableDurableStorage();
  readonly attempts: Set<string>[] = [];
  corruptBlobReads = false;

  transaction<Result>(callback: (transaction: TransactionPort) => Promise<Result>): Promise<Result> {
    return this.backing.transaction(async (transaction) => {
      const keys = new Set<string>();
      this.attempts.push(keys);
      return callback({
        get: async <Value>(key: string) => {
          const value = await transaction.get<Value>(key);
          if (this.corruptBlobReads && key.includes(".blob.") && value instanceof Uint8Array) {
            const corrupted = value.slice();
            corrupted[0] ^= 1;
            return corrupted as Value;
          }
          return value;
        },
        put: async <Value>(key: string, value: Value) => {
          keys.add(key);
          await transaction.put(key, value);
        },
        delete: async (key: string) => {
          keys.add(key);
          return transaction.delete(key);
        },
      });
    });
  }
}

interface StoredPayloadOutcome {
  readonly digest: Digest;
}

interface PayloadState {
  version: number;
  receipt: StoredPayloadOutcome | null;
  references: Digest[];
}

type PayloadCommand = { readonly value: number } | { readonly replay: true };

function payloadAdapter(options: {
  readonly onMaterialize?: () => void;
  readonly outcomeDigest?: Digest;
  readonly failMaterialization?: () => boolean;
} = {}): AggregateAdapter<PayloadState, null, PayloadCommand, StoredPayloadOutcome, { value: number }> {
  return {
    kind: "payload-outcome-test",
    create: () => ({ version: 0, receipt: null, references: [] }),
    validate: (state) => {
      if (!Number.isSafeInteger(state.version) || state.version < 0) throw new Error("invalid state");
    },
    version: (state) => state.version,
    apply: async (state, command) => {
      if ("replay" in command) {
        if (state.receipt === null) throw new Error("no receipt");
        return { state, outcome: state.receipt, replayed: true };
      }
      const bytes = encodeCanonicalCbor({ value: command.value });
      const digest = await digestBytes(bytes);
      const outcome = { digest: options.outcomeDigest ?? digest };
      return {
        state: { version: state.version + 1, receipt: outcome, references: [digest] },
        outcome,
        replayed: false,
        blobs: new Map([[digest, bytes]]),
        referencedBlobs: [digest],
      };
    },
    materializeOutcome: async (outcome, { readBlob }) => {
      options.onMaterialize?.();
      const bytes = await readBlob(outcome.digest);
      if (bytes === undefined) throw new HostContractError("CORRUPT_STATE", "receipt payload is not referenced");
      if (options.failMaterialization?.()) throw new Error("injected outcome materialization failure");
      return decodeCanonicalCbor(bytes) as { value: number };
    },
  };
}

describe("transactional outcome materialization", () => {
  it("uses the same blob-backed wire outcome for first delivery and receipt replay after restart", async () => {
    const storage = new ObservedStorage();
    let materializations = 0;
    const adapter = payloadAdapter({ onMaterialize: () => { materializations += 1; } });
    const kernel = new TransactionalAggregateKernel({ storage }, adapter);
    await kernel.initialize(null);
    expect(await kernel.execute({ value: 42 })).toEqual({ outcome: { value: 42 }, version: 1, replayed: false });
    const durableVersion = storage.backing.durableRevision;
    const restarted = new TransactionalAggregateKernel({ storage: storage.backing.restart() }, adapter);
    expect(await restarted.execute({ replay: true })).toEqual({ outcome: { value: 42 }, version: 1, replayed: true });
    expect(materializations).toBe(2);
    expect(storage.backing.durableRevision).toBe(durableVersion);
    const stored = await restarted.query(null, (state) => state);
    expect(stored.receipt).toEqual({ digest: await digestBytes(encodeCanonicalCbor({ value: 42 })) });
    expect(stored.receipt).not.toHaveProperty("value");
  });

  it("rolls back state and newly created blobs when wire materialization fails", async () => {
    const storage = new ObservedStorage();
    let fail = true;
    const kernel = new TransactionalAggregateKernel({ storage }, payloadAdapter({ failMaterialization: () => fail }));
    await kernel.initialize(null);
    const entriesBefore = storage.backing.durableEntryCount;
    const revisionBefore = storage.backing.durableRevision;
    await expect(kernel.execute({ value: 42 })).rejects.toThrow("injected outcome materialization failure");
    expect(storage.backing.durableEntryCount).toBe(entriesBefore);
    expect(storage.backing.durableRevision).toBe(revisionBefore);
    expect(await kernel.query(null, (state) => state)).toEqual({ version: 0, receipt: null, references: [] });
    fail = false;
    expect(await kernel.execute({ value: 42 })).toMatchObject({ outcome: { value: 42 }, replayed: false });
  });

  it("requires current manifest membership even if an unreferenced blob row exists", async () => {
    const storage = new ObservedStorage();
    const orphanBytes = encodeCanonicalCbor({ value: 99 });
    const orphanDigest = await digestBytes(orphanBytes);
    const kernel = new TransactionalAggregateKernel({ storage }, payloadAdapter({ outcomeDigest: orphanDigest }));
    await kernel.initialize(null);
    await storage.backing.transaction((transaction) => transaction.put(
      `circulusd.state-app.aggregate.v2.blob.${orphanDigest}.000`, orphanBytes,
    ));
    const entriesBefore = storage.backing.durableEntryCount;
    const revisionBefore = storage.backing.durableRevision;
    await expect(kernel.execute({ value: 42 })).rejects.toMatchObject({ code: "CORRUPT_STATE" });
    expect(storage.backing.durableEntryCount).toBe(entriesBefore);
    expect(storage.backing.durableRevision).toBe(revisionBefore);
  });

  it("verifies newly written blob digests before allowing the enclosing command to commit", async () => {
    const storage = new ObservedStorage();
    const kernel = new TransactionalAggregateKernel({ storage }, payloadAdapter());
    await kernel.initialize(null);
    const entriesBefore = storage.backing.durableEntryCount;
    const revisionBefore = storage.backing.durableRevision;
    storage.corruptBlobReads = true;
    await expect(kernel.execute({ value: 42 })).rejects.toMatchObject({ code: "CORRUPT_STATE" });
    expect(storage.backing.durableEntryCount).toBe(entriesBefore);
    expect(storage.backing.durableRevision).toBe(revisionBefore);
  });

  it("replays the original wire result after commit succeeds and the caller loses the response", async () => {
    const storage = new ObservedStorage();
    const adapter = payloadAdapter();
    const kernel = new TransactionalAggregateKernel({ storage }, adapter);
    await kernel.initialize(null);
    storage.backing.injectCrashOnce("after-commit-before-result");
    await expect(kernel.execute({ value: 42 })).rejects.toMatchObject({ phase: "after-commit-before-result" });
    const durableVersion = storage.backing.durableRevision;
    const restarted = new TransactionalAggregateKernel({ storage: storage.backing.restart() }, adapter);
    expect(await restarted.execute({ replay: true })).toEqual({ outcome: { value: 42 }, version: 1, replayed: true });
    expect(storage.backing.durableRevision).toBe(durableVersion);
  });
});

interface MigrationState {
  schema: number;
  version: number;
  references: Digest[];
}

describe("whole-transaction mutation budget", () => {
  it.each([128, 129])("enforces %i distinct mutated keys across migration plus command", async (totalKeys) => {
    const migrationBlobs = new Map<Digest, Uint8Array>();
    const commandBlobs = new Map<Digest, Uint8Array>();
    // Besides the blobs, the callback touches the old, migrated, and final
    // state chunks plus the shared manifest: four distinct metadata keys.
    for (let index = 0; index < totalKeys - 4; index += 1) {
      const bytes = Uint8Array.of(index);
      (index < 61 ? migrationBlobs : commandBlobs).set(await digestBytes(bytes), bytes);
    }
    const legacyAdapter: AggregateAdapter<MigrationState, null, null, number> = {
      kind: "migration-budget-test",
      create: () => ({ schema: 1, version: 0, references: [] }),
      validate: (state) => {
        if ((state.schema !== 1 && state.schema !== 2) || state.version < 0) throw new Error("invalid state");
      },
      version: (state) => state.version,
      apply: async () => { throw new Error("legacy adapter cannot execute"); },
    };
    const migratedAdapter: typeof legacyAdapter = {
      ...legacyAdapter,
      migrate: (input) => {
        const state = input as MigrationState;
        if (state.schema === 2) return { state, migrated: false };
        return {
          state: { ...state, schema: 2, references: [...migrationBlobs.keys()] },
          migrated: true,
          blobs: migrationBlobs,
          referencedBlobs: [...migrationBlobs.keys()],
        };
      },
      apply: async (state) => {
        const next = { ...state, version: state.version + 1, references: [...state.references, ...commandBlobs.keys()] };
        return { state: next, outcome: next.version, replayed: false, blobs: commandBlobs, referencedBlobs: next.references };
      },
    };
    const storage = new ObservedStorage();
    const legacy = new TransactionalAggregateKernel({ storage }, legacyAdapter);
    await legacy.initialize(null);
    const revisionBefore = storage.backing.durableRevision;
    const entriesBefore = storage.backing.durableEntryCount;
    const current = new TransactionalAggregateKernel({ storage }, migratedAdapter);
    if (totalKeys === 128) {
      expect(await current.execute(null)).toEqual({ outcome: 1, version: 1, replayed: false });
      expect(storage.attempts.at(-1)?.size).toBe(128);
      expect(storage.backing.durableRevision).toBe(revisionBefore + 1);
      expect(await current.query(null, (state) => state.schema)).toBe(2);
    } else {
      await expect(current.execute(null)).rejects.toMatchObject({ code: "INVALID_AGGREGATE_OUTPUT" });
      expect(storage.backing.durableRevision).toBe(revisionBefore);
      expect(storage.backing.durableEntryCount).toBe(entriesBefore);
      expect(await legacy.query(null, (state) => state)).toEqual({ schema: 1, version: 0, references: [] });
    }
  });
});
