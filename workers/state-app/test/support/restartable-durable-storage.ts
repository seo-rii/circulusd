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

interface ScheduledCommitCrash {
  readonly phase: InjectedCommitCrashPhase;
  remainingMutatingCommits: number;
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
  #scheduledCrash: ScheduledCommitCrash | undefined;

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
    this.injectCrashOnMutatingCommit(1, phase);
  }

  injectCrashOnMutatingCommit(
    mutatingCommit: number,
    phase: InjectedCommitCrashPhase,
  ): void {
    if (!Number.isSafeInteger(mutatingCommit) || mutatingCommit < 1) {
      throw new RangeError("mutatingCommit must be a positive safe integer");
    }
    if (this.#scheduledCrash !== undefined) {
      throw new Error("a commit crash is already armed");
    }
    this.#scheduledCrash = {
      phase,
      remainingMutatingCommits: mutatingCommit,
    };
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
      let crashAtThisCommit: InjectedCommitCrashPhase | undefined;
      if (mutated && this.#scheduledCrash !== undefined) {
        if (this.#scheduledCrash.remainingMutatingCommits === 1) {
          crashAtThisCommit = this.#scheduledCrash.phase;
          this.#scheduledCrash = undefined;
        } else {
          this.#scheduledCrash.remainingMutatingCommits -= 1;
        }
      }
      if (crashAtThisCommit === "before-commit") {
        throw new InjectedDurableStorageCrash(crashAtThisCommit);
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
      if (crashAtThisCommit === "after-commit-before-result") {
        throw new InjectedDurableStorageCrash(crashAtThisCommit);
      }
      return structuredClone(result);
    }
    throw new Error("reference transaction retry limit exceeded");
  }
}
