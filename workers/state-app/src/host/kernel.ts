import { digestStructuredValue, type Digest } from "@circulusd/protocol-types";

import {
  HostContractError,
  type AggregateAdapter,
  type AggregateApplyContext,
  type CellRoutePort,
  type CommittedCommandResult,
  type DurableObjectStatePort,
  type InitializationResult,
  type TransactionalStoragePort,
  type TransactionPort,
} from "./contracts.ts";
import {
  ChunkedAggregateStorage,
  type StateRecord,
  type StoredStateRecord,
} from "./storage.ts";

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
  return transaction;
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

export class TransactionalAggregateKernel<State, Initialization, Command, Outcome> {
  private readonly storage: TransactionalStoragePort;
  private readonly adapter: AggregateAdapter<State, Initialization, Command, Outcome>;
  private readonly records: ChunkedAggregateStorage<State>;
  private readonly clock: () => number;

  constructor(
    state: DurableObjectStatePort,
    adapter: AggregateAdapter<State, Initialization, Command, Outcome>,
    route?: CellRoutePort,
    clock: () => number = Date.now,
  ) {
    this.storage = transactionalStorage(state);
    this.adapter = adapter;
    this.clock = clock;
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

  async execute(command: Command): Promise<CommittedCommandResult<Outcome>> {
    const commandSnapshot = cloneBoundary(command, "command input");
    const result = await this.transact(async (transaction) => {
      const context: AggregateApplyContext = {
        transactionTime: checkedTransactionTime(this.clock()),
      };
      const stored = await this.loadInitialized(transaction);
      const { record } = stored;
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
      const committed: CommittedCommandResult<Outcome> = {
        outcome: cloneBoundary(applied.outcome, "aggregate outcome"),
        version: checkedVersion(this.adapter.version(nextState)),
        replayed: applied.replayed,
      };
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
        await this.records.write(transaction, nextRecord, stored.manifest);
      }
      return committed;
    });
    return cloneBoundary(result, "committed command result");
  }

  async query<Input, Result>(
    input: Input,
    reader: (state: State, input: Input) => Result | Promise<Result>,
  ): Promise<Result> {
    const inputSnapshot = cloneBoundary(input, "read input");
    const result = await this.transact(async (transaction) => {
      const { record } = await this.loadInitialized(transaction);
      return reader(
        cloneBoundary(record.state, "stored aggregate state"),
        cloneBoundary(inputSnapshot, "read input"),
      );
    });
    return cloneBoundary(result, "read result");
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
