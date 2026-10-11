import { digestStructuredValue, type Digest } from "@circulusd/protocol-types";

import {
  HostContractError,
  ArchivePlanningLimitError,
  type AggregateAdapter,
  type AggregateApplyContext,
  type AggregateApplyResult,
  type CellRoutePort,
  type CommittedCommandResult,
  type DurableObjectStatePort,
  type InitializationResult,
  type TransactionalStoragePort,
  type TransactionPort,
} from "./contracts.ts";
import {
  ChunkedAggregateStorage,
  MAX_TRANSACTION_MUTATED_KEYS,
  type StateRecord,
  type StoredStateRecord,
} from "./storage.ts";
import type { SessionHistoryIndexRoot } from "./session-history-index.ts";

export interface AggregateQueryContext<State> {
  readonly transaction: TransactionPort;
  readonly stored: StoredStateRecord<State>;
  readBlob(digest: Digest): Promise<Uint8Array | undefined>;
}

export interface AggregateTransactionCompanion<State, Command, StoredOutcome,
  Context extends AggregateApplyContext,
  Applied extends AggregateApplyResult<State, StoredOutcome>> {
  prepareContext(transaction: TransactionPort, stored: StoredStateRecord<State>,
    command: Command, context: AggregateApplyContext): Promise<Context>;
  persist(transaction: TransactionPort, stored: StoredStateRecord<State>,
    command: Command, applied: Applied): Promise<SessionHistoryIndexRoot>;
  reduceArchiveBatch?(context: Context): Context | undefined;
}

const transactionMutationKeys = new WeakMap<TransactionPort, Set<string>>();
class MutationBudgetError extends ArchivePlanningLimitError {
  constructor() { super("aggregate transaction exceeds the mutated-key limit"); }
}

// Plan Session archive/index/blob/state mutations before issuing any of them.
// Reads see the proposed writes, and the final key set includes read migrations.
class PlannedTransaction implements TransactionPort {
  readonly #base: TransactionPort;
  readonly #writes = new Map<string, { value: unknown } | null>();
  constructor(base: TransactionPort) { this.#base = base; }
  async get<Value>(key: string): Promise<Value | undefined> {
    if (this.#writes.has(key)) {
      const pending = this.#writes.get(key);
      return pending === null ? undefined : structuredClone(pending!.value) as Value;
    }
    return this.#base.get<Value>(key);
  }
  #reserve(key: string): void {
    const keys = new Set([...transactionMutationKeys.get(this.#base) ?? [], ...this.#writes.keys(), key]);
    if (keys.size > MAX_TRANSACTION_MUTATED_KEYS) throw new MutationBudgetError();
  }
  async put<Value>(key: string, value: Value): Promise<void> {
    this.#reserve(key);
    this.#writes.set(key, { value: structuredClone(value) });
  }
  async delete(key: string): Promise<boolean> {
    const present = await this.get(key) !== undefined;
    this.#reserve(key);
    this.#writes.set(key, null);
    return present;
  }
  async flush(): Promise<void> {
    for (const [key, write] of this.#writes) {
      if (write === null) await this.#base.delete(key);
      else await this.#base.put(key, write.value);
    }
  }
}

function cloneBoundary<Value>(value: Value, label: string): Value {
  try {
    return structuredClone(value);
  } catch (error) {
    throw new HostContractError(
      "STRUCTURED_CLONE_FAILED",
      `${label} is not structured-cloneable`,
      { cause: error },
    );
  }
}

function transactionalStorage(state: DurableObjectStatePort): TransactionalStoragePort {
  if (typeof state !== "object" || state === null) {
    throw new HostContractError(
      "STORAGE_CONTRACT",
      "Durable Object state must provide transactional storage",
    );
  }
  const storage = (state as { readonly storage?: unknown }).storage;
  if (
    typeof storage !== "object" ||
    storage === null ||
    typeof (storage as { readonly transaction?: unknown }).transaction !== "function"
  ) {
    throw new HostContractError(
      "STORAGE_CONTRACT",
      "Durable Object storage must provide transaction(callback)",
    );
  }
  return storage as TransactionalStoragePort;
}

function checkedTransaction(transaction: TransactionPort): TransactionPort {
  if (
    typeof transaction !== "object" ||
    transaction === null ||
    typeof (transaction as { readonly get?: unknown }).get !== "function" ||
    typeof (transaction as { readonly put?: unknown }).put !== "function" ||
    typeof (transaction as { readonly delete?: unknown }).delete !== "function"
  ) {
    throw new HostContractError(
      "STORAGE_CONTRACT",
      "storage transaction must provide get(key), put(key, value), and delete(key)",
    );
  }
  // A migration during read and the subsequent command can each fit the write
  // planner while their combined write-set exceeds the transaction limit. Share
  // one distinct-key budget across all operations in this callback attempt.
  const mutatedKeys = new Set<string>();
  const reserveKey = (key: string): void => {
    if (!mutatedKeys.has(key) && mutatedKeys.size >= MAX_TRANSACTION_MUTATED_KEYS) {
      throw new MutationBudgetError();
    }
    mutatedKeys.add(key);
  };
  const checked: TransactionPort = {
    get: <Value>(key: string) => transaction.get<Value>(key),
    put: <Value>(key: string, value: Value) => {
      reserveKey(key);
      return transaction.put(key, value);
    },
    delete: (key: string) => {
      reserveKey(key);
      return transaction.delete(key);
    },
  };
  transactionMutationKeys.set(checked, mutatedKeys);
  return checked;
}

function checkedVersion(version: number): number {
  if (!Number.isSafeInteger(version) || version < 0) {
    throw new HostContractError(
      "INVALID_AGGREGATE_OUTPUT",
      "aggregate version must be a non-negative safe integer",
    );
  }
  return version;
}

function checkedTransactionTime(transactionTime: number): number {
  if (!Number.isSafeInteger(transactionTime) || transactionTime < 0) {
    throw new HostContractError(
      "INVALID_AGGREGATE_OUTPUT",
      "host transaction time must be a non-negative safe integer",
    );
  }
  return transactionTime;
}

export class TransactionalAggregateKernel<
  State,
  Initialization,
  Command,
  StoredOutcome,
  WireOutcome = StoredOutcome,
  Context extends AggregateApplyContext = AggregateApplyContext,
  Applied extends AggregateApplyResult<State, StoredOutcome> = AggregateApplyResult<State, StoredOutcome>,
> {
  private readonly storage: TransactionalStoragePort;
  private readonly adapter: AggregateAdapter<State, Initialization, Command, StoredOutcome, WireOutcome, Context, Applied>;
  private readonly records: ChunkedAggregateStorage<State>;
  private readonly clock: () => number;
  private readonly companion: AggregateTransactionCompanion<State, Command, StoredOutcome, Context, Applied> | undefined;

  constructor(
    state: DurableObjectStatePort,
    adapter: AggregateAdapter<State, Initialization, Command, StoredOutcome, WireOutcome, Context, Applied>,
    route?: CellRoutePort,
    clock: () => number = Date.now,
    companion?: AggregateTransactionCompanion<State, Command, StoredOutcome, Context, Applied>,
  ) {
    this.storage = transactionalStorage(state);
    this.adapter = adapter;
    this.clock = clock;
    this.companion = companion;
    this.records = new ChunkedAggregateStorage(
      adapter.kind,
      adapter.validate,
      route,
      adapter.migrate,
    );
  }

  async initialize(initialization: Initialization): Promise<InitializationResult> {
    const initializationSnapshot = cloneBoundary(initialization, "initialization input");
    const candidate = this.adapter.create(initializationSnapshot);
    await this.adapter.validate(candidate);
    const candidateSnapshot = cloneBoundary(candidate, "initial aggregate state");
    const initializationDigest = await digestStructuredValue(
      `circulusd.state-app.${this.adapter.kind}-initialization`,
      1,
      initializationSnapshot,
    );
    const candidateRecord = this.records.buildInitialRecord(
      initializationDigest,
      candidateSnapshot,
      this.adapter.cellName?.(initializationSnapshot),
    );

    const result = await this.transact(async (transaction) => {
      const stored = await this.records.read(transaction);
      if (stored === undefined) {
        await this.records.write(transaction, candidateRecord);
        return {
          version: checkedVersion(this.adapter.version(candidateSnapshot)),
          replayed: false,
        } satisfies InitializationResult;
      }

      const { record } = stored;
      if (record.initializationDigest !== initializationDigest) {
        throw new HostContractError(
          "INITIALIZATION_CONFLICT",
          `${this.adapter.kind} cell was initialized with a different canonical digest`,
        );
      }
      return {
        version: checkedVersion(this.adapter.version(record.state)),
        replayed: true,
      } satisfies InitializationResult;
    });
    return cloneBoundary(result, "initialization result");
  }

  async execute(command: Command): Promise<CommittedCommandResult<WireOutcome>> {
    const commandSnapshot = cloneBoundary(command, "command input");
    const result = await this.transact(async (transaction) => {
      const baseContext: AggregateApplyContext = {
        transactionTime: checkedTransactionTime(this.clock()),
      };
      const stored = await this.loadInitialized(transaction);
      const { record } = stored;
      let context = this.companion === undefined
        ? baseContext as Context
        : await this.companion.prepareContext(transaction, stored, commandSnapshot, baseContext);
      for (;;) {
        const applied = await this.adapter.apply(
          cloneBoundary(record.state, "stored aggregate state"),
          cloneBoundary(commandSnapshot, "command input"),
          context,
        );
        if (
          typeof applied !== "object" ||
          applied === null ||
          typeof applied.replayed !== "boolean" ||
          !("state" in applied) ||
          !("outcome" in applied)
        ) {
          throw new HostContractError(
            "INVALID_AGGREGATE_OUTPUT",
            "aggregate apply returned an invalid result",
          );
        }
        const nextState = cloneBoundary(applied.state, "aggregate output state");
        try {
          await this.adapter.validate(nextState);
        } catch (error) {
          throw new HostContractError(
            "INVALID_AGGREGATE_OUTPUT",
            "aggregate apply returned invalid state",
            { cause: error },
          );
        }
        const version = checkedVersion(this.adapter.version(nextState));
        if (applied.replayed) {
          let storedDigest: Digest;
          let replayDigest: Digest;
          try {
            [storedDigest, replayDigest] = await Promise.all([
              digestStructuredValue(
                `circulusd.state-app.${this.adapter.kind}-replay-state`,
                1,
                record.state,
              ),
              digestStructuredValue(
                `circulusd.state-app.${this.adapter.kind}-replay-state`,
                1,
                nextState,
              ),
            ]);
          } catch (error) {
            throw new HostContractError(
              "INVALID_AGGREGATE_OUTPUT",
              "aggregate replay state is not canonically digestible",
              { cause: error },
            );
          }
          if (storedDigest !== replayDigest) {
            throw new HostContractError(
              "INVALID_AGGREGATE_OUTPUT",
              "aggregate replay attempted to change committed state",
            );
          }
        } else {
          const nextRecord: StateRecord<State> = {
            ...record,
            state: nextState,
          };
          let blobs: ReadonlyMap<Digest, Uint8Array> | undefined;
          if (applied.blobs !== undefined) {
            if (!(applied.blobs instanceof Map)) {
              throw new HostContractError(
                "INVALID_AGGREGATE_OUTPUT",
                "aggregate blobs must be a Map keyed by content digest",
              );
            }
            blobs = cloneBoundary(applied.blobs, "aggregate output blobs");
          }
          let referencedBlobs: readonly Digest[] | undefined;
          if (applied.referencedBlobs !== undefined) {
            if (!Array.isArray(applied.referencedBlobs)) {
              throw new HostContractError(
                "INVALID_AGGREGATE_OUTPUT",
                "aggregate referencedBlobs must be an array of content digests",
              );
            }
            referencedBlobs = cloneBoundary(
              applied.referencedBlobs,
              "aggregate referenced blobs",
            );
          }
          const planned = this.companion === undefined ? undefined : new PlannedTransaction(transaction);
          const writer = planned ?? transaction;
          try {
            const sessionHistory = this.companion === undefined ? undefined
              : await this.companion.persist(writer, stored, commandSnapshot, applied);
            await this.records.write(
              writer,
              nextRecord,
              stored.manifest,
              blobs,
              referencedBlobs,
              sessionHistory,
            );
            await planned?.flush();
          } catch (error) {
            if (planned !== undefined && error instanceof ArchivePlanningLimitError) {
              const reduced = this.companion?.reduceArchiveBatch?.(context);
              if (reduced !== undefined) { context = reduced; continue; }
            }
            throw error;
          }
        }
        const storedOutcome = cloneBoundary(applied.outcome, "stored aggregate outcome");
        const wireOutcome = this.adapter.materializeOutcome === undefined
          ? storedOutcome as unknown as WireOutcome
          : await this.adapter.materializeOutcome(storedOutcome, {
              readBlob: (digest) => this.records.readBlob(transaction, digest),
            });
        return {
          outcome: cloneBoundary(wireOutcome, "aggregate wire outcome"),
          version,
          replayed: applied.replayed,
        } satisfies CommittedCommandResult<WireOutcome>;
      }
    });
    return cloneBoundary(result, "committed command result");
  }

  async query<Input, Result>(
    input: Input,
    reader: (state: State, input: Input, context: AggregateQueryContext<State>) => Result | Promise<Result>,
  ): Promise<Result> {
    const inputSnapshot = cloneBoundary(input, "read input");
    const result = await this.transact(async (transaction) => {
      const stored = await this.loadInitialized(transaction);
      const { record } = stored;
      return reader(
        cloneBoundary(record.state, "stored aggregate state"),
        cloneBoundary(inputSnapshot, "read input"),
        { transaction, stored, readBlob: (digest) => this.records.readBlob(transaction, digest) },
      );
    });
    return cloneBoundary(result, "read result");
  }

  // Read one externalized payload blob (storage redesign stage B) inside the same
  // transaction as the state it is authorized against: `authorize` sees the stored
  // state and the query exactly like a `query` reader, and only then is the blob
  // the query names looked up. Returns undefined when neither the hot state nor
  // its authenticated archive owns that digest. Superseded unarchived payloads
  // and orphan storage rows cannot be read through this boundary.
  async queryBlob<Input>(
    input: Input,
    authorize: (state: State, input: Input) => void | Promise<void>,
    digestOf: (input: Input) => Digest,
  ): Promise<Uint8Array | undefined> {
    const inputSnapshot = cloneBoundary(input, "read input");
    const result = await this.transact(async (transaction) => {
      const { record } = await this.loadInitialized(transaction);
      const query = cloneBoundary(inputSnapshot, "read input");
      await authorize(cloneBoundary(record.state, "stored aggregate state"), query);
      return this.records.readBlob(transaction, digestOf(query));
    });
    return result === undefined ? undefined : cloneBoundary(result, "read result");
  }

  private async loadInitialized(
    transaction: TransactionPort,
  ): Promise<StoredStateRecord<State>> {
    const stored = await this.records.read(transaction);
    if (stored === undefined) {
      throw new HostContractError(
        "NOT_INITIALIZED",
        `${this.adapter.kind} cell is not initialized`,
      );
    }
    return stored;
  }

  private async transact<Result>(
    callback: (transaction: TransactionPort) => Promise<Result>,
  ): Promise<Result> {
    let callbackInvocations = 0;
    let callbackCompletions = 0;
    const result = await this.storage.transaction(async (candidateTransaction) => {
      callbackInvocations += 1;
      const transaction = checkedTransaction(candidateTransaction);
      const callbackResult = await callback(transaction);
      callbackCompletions += 1;
      return callbackResult;
    });
    if (callbackInvocations === 0 || callbackCompletions !== callbackInvocations) {
      throw new HostContractError(
        "STORAGE_CONTRACT",
        "storage transaction returned without a completed callback",
      );
    }
    return result;
  }

}
