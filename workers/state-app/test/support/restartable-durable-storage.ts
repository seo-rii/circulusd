import type {
  TransactionalStoragePort,
  TransactionPort,
} from "../../src/host/contracts.ts";

export type InjectedCommitCrashPhase =
  | "before-commit"
  | "after-commit-before-result";

export const RESTARTABLE_DURABLE_STORAGE_EVIDENCE = Object.freeze({
  kind: "deterministic-restartable-transactional-storage",
  referenceOnly: true,
  productionEligible: false,
  conformanceClaimed: false,
} as const);

export class InjectedDurableStorageCrash extends Error {
  readonly phase: InjectedCommitCrashPhase;

  constructor(phase: InjectedCommitCrashPhase) {
    super(`injected Durable Object storage crash at ${phase}`);
    this.name = "InjectedDurableStorageCrash";
    this.phase = phase;
  }
}

interface DurableBacking {
  readonly values: Map<string, unknown>;
  revision: number;
}

/**
 * Deterministic reference storage for fault-boundary tests only.
 *
 * Async transaction callbacks may interleave. A revision check then commits the
 * complete staged write-set atomically or retries it against a fresh snapshot.
 * This model does not emulate the Cloudflare runtime or qualify production DO
 * behavior; its evidence is deliberately marked reference-only above.
 */
export class RestartableDurableStorage implements TransactionalStoragePort {
  readonly evidence = RESTARTABLE_DURABLE_STORAGE_EVIDENCE;
  readonly #backing: DurableBacking;
  #nextCrash: InjectedCommitCrashPhase | undefined;

  constructor(source?: RestartableDurableStorage) {
    this.#backing = source === undefined
      ? {
          values: new Map<string, unknown>(),
          revision: 0,
        }
      : source.#backing;
  }

  get durableEntryCount(): number {
    return this.#backing.values.size;
  }

  get durableRevision(): number {
    return this.#backing.revision;
  }

  restart(): RestartableDurableStorage {
    return new RestartableDurableStorage(this);
  }

  injectCrashOnce(phase: InjectedCommitCrashPhase): void {
    if (this.#nextCrash !== undefined) {
      throw new Error("a commit crash is already armed");
    }
    this.#nextCrash = phase;
  }

  async transaction<Result>(
    callback: (transaction: TransactionPort) => Promise<Result>,
  ): Promise<Result> {
    for (let attempt = 0; attempt < 32; attempt += 1) {
      const expectedRevision = this.#backing.revision;
      const snapshot = new Map<string, unknown>();
      for (const [key, value] of this.#backing.values) {
        snapshot.set(key, structuredClone(value));
      }
      const writes = new Map<string, unknown>();
      const deletes = new Set<string>();
      const transaction: TransactionPort = {
        get: async <Value>(key: string) => {
          const value = deletes.has(key)
            ? undefined
            : writes.has(key)
              ? writes.get(key)
              : snapshot.get(key);
          return value === undefined
            ? undefined
            : structuredClone(value) as Value;
        },
        put: async <Value>(key: string, value: Value) => {
          deletes.delete(key);
          writes.set(key, structuredClone(value));
        },
        delete: async (key: string) => {
          const existed = !deletes.has(key) &&
            (writes.has(key) || snapshot.has(key));
          writes.delete(key);
          deletes.add(key);
          return existed;
        },
      };

      const result = await callback(transaction);
      if (expectedRevision !== this.#backing.revision) {
        continue;
      }
      const mutated = writes.size > 0 || deletes.size > 0;
      if (mutated && this.#nextCrash === "before-commit") {
        this.#nextCrash = undefined;
        throw new InjectedDurableStorageCrash("before-commit");
      }
      if (mutated) {
        for (const key of deletes) {
          this.#backing.values.delete(key);
        }
        for (const [key, value] of writes) {
          this.#backing.values.set(key, structuredClone(value));
        }
        this.#backing.revision += 1;
      }
      if (mutated && this.#nextCrash === "after-commit-before-result") {
        this.#nextCrash = undefined;
        throw new InjectedDurableStorageCrash("after-commit-before-result");
      }
      return structuredClone(result);
    }
    throw new Error("reference transaction retry limit exceeded");
  }
}
