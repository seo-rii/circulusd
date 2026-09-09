import type { Digest } from "@circulusd/protocol-types";

export type HostContractErrorCode =
  | "STORAGE_CONTRACT"
  | "CELL_ID_MISMATCH"
  | "NOT_INITIALIZED"
  | "INITIALIZATION_CONFLICT"
  | "STRUCTURED_CLONE_FAILED"
  | "CORRUPT_STATE"
  | "INVALID_AGGREGATE_OUTPUT";

export class HostContractError extends Error {
  readonly code: HostContractErrorCode;

  constructor(code: HostContractErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "HostContractError";
    this.code = code;
  }
}

export interface TransactionPort {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
}

export interface TransactionalStoragePort {
  transaction<T>(callback: (transaction: TransactionPort) => Promise<T>): Promise<T>;
}

export interface DurableObjectStatePort {
  readonly storage: TransactionalStoragePort;
  readonly id?: DurableObjectIdPort;
}

export interface DurableObjectIdPort {
  equals(other: unknown): boolean;
  toString(): string;
}

export interface DurableObjectNamespacePort {
  idFromName(name: string): DurableObjectIdPort;
}

export interface CellRoutePort {
  readonly currentId: DurableObjectIdPort;
  readonly namespace: DurableObjectNamespacePort;
}

export interface InitializationResult {
  readonly version: number;
  readonly replayed: boolean;
}

export interface CommittedCommandResult<Outcome> {
  readonly outcome: Outcome;
  readonly version: number;
  readonly replayed: boolean;
}

// Payload externalization side channel (storage redesign stage B). A pure
// aggregate cannot perform blob I/O, so it validates and digests a large payload,
// stores a fixed-size reference in its state, and returns the raw bytes here for
// the host kernel to persist as digest-keyed blob rows in the same durable
// transaction as the state. `blobs` are the NEW bytes to persist this write, keyed
// by their content digest; `referencedBlobs` is the COMPLETE set of blob digests
// the returned `state` references, from which the storage layer derives which blob
// rows to create and which are now unreferenced and can be deleted.
export interface AggregateBlobEffects {
  readonly blobs?: ReadonlyMap<Digest, Uint8Array>;
  readonly referencedBlobs?: readonly Digest[];
}

export interface AggregateApplyResult<State, Outcome> extends AggregateBlobEffects {
  readonly state: State;
  readonly outcome: Outcome;
  readonly replayed: boolean;
}

export interface AggregateMigrationResult<State> extends AggregateBlobEffects {
  readonly state: State;
  readonly migrated: boolean;
}

export interface AggregateApplyContext {
  readonly transactionTime: number;
}

export interface AggregateAdapter<State, Initialization, Command, Outcome> {
  readonly kind: string;
  cellName?(initialization: Initialization): string;
  create(initialization: Initialization): State;
  migrate?(
    state: unknown,
  ): AggregateMigrationResult<State> | Promise<AggregateMigrationResult<State>>;
  validate(state: State): void | Promise<void>;
  apply(
    state: State,
    command: Command,
    context: AggregateApplyContext,
  ): Promise<AggregateApplyResult<State, Outcome>>;
  version(state: State): number;
}
