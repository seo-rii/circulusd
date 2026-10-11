import type { Digest } from "@circulusd/protocol-types";

export const MAXIMUM_REVISION = Number.MAX_SAFE_INTEGER;
export const MAXIMUM_BOUNDS = Object.freeze({
  maxStateBytes: 16 << 20,
  maxReceiptResponseBytes: 4 << 20,
  maxCapabilityClaims: 64,
  maxCapabilityClaimBytes: 1 << 20,
  maxReceiptLookups: 64,
  maxReceiptWrites: 64,
  maxTransactionBytes: 32 << 20,
});
export type NativeStorageBounds = { readonly [Key in keyof typeof MAXIMUM_BOUNDS]: number };
export type NativeStorageBoundsInput = Partial<NativeStorageBounds>;

export function resolveNativeStorageBounds(input: NativeStorageBoundsInput = {}): NativeStorageBounds {
  const result: { -readonly [Key in keyof NativeStorageBounds]: number } = { ...MAXIMUM_BOUNDS };
  for (const key of Object.keys(MAXIMUM_BOUNDS) as (keyof NativeStorageBounds)[]) {
    const value = input[key] ?? MAXIMUM_BOUNDS[key];
    if (!Number.isSafeInteger(value) || value < 1 || value > MAXIMUM_BOUNDS[key]) {
      throw new NativeStorageError("INVALID_ARGUMENT");
    }
    result[key] = value;
  }
  if (Object.keys(input).some((key) => !Object.hasOwn(MAXIMUM_BOUNDS, key))) {
    throw new NativeStorageError("INVALID_ARGUMENT");
  }
  return Object.freeze(result);
}

export type NativeStorageErrorCode = "INVALID_ARGUMENT" | "SNAPSHOT_CONFLICT" | "RECEIPT_CONFLICT" | "CORRUPT_STATE" | "UNAVAILABLE";
export class NativeStorageError extends Error {
  readonly code: NativeStorageErrorCode;
  constructor(code: NativeStorageErrorCode) {
    super("Native storage operation failed.");
    this.name = "NativeStorageError";
    this.code = code;
  }
}

export interface SnapshotRef {
  readonly objectId: string;
  readonly exists: boolean;
  readonly revision: number;
  readonly stateDigest: Digest;
}
export interface Snapshot extends SnapshotRef { readonly state: Uint8Array }
export interface StoredReceipt {
  readonly commandDigest: Digest;
  readonly response: Uint8Array;
  readonly capabilityClaims: readonly { readonly kind: string; readonly payload: Uint8Array }[];
}
export interface ReceiptWrite { readonly commandId: string; readonly receipt: StoredReceipt }
export interface CommitToken { readonly objectId: string; readonly revision: number }
export interface CommitRequest {
  readonly snapshot: SnapshotRef;
  readonly stateWritten: boolean;
  readonly state: Uint8Array;
  readonly receipts: readonly ReceiptWrite[];
  readonly requestDigest: Digest;
}
export interface CommitResult {
  readonly snapshot: SnapshotRef;
  readonly requestDigest: Digest;
  readonly token: CommitToken;
}
export interface BarrierRequest { readonly token: CommitToken; readonly marker: Uint8Array }
export interface BarrierResult extends BarrierRequest {
  readonly observedRevision: number;
  readonly barrierSerial: number;
}
export interface ReceiptRequest { readonly snapshot: SnapshotRef; readonly commandId: string }
export interface ReceiptResult extends ReceiptRequest {
  readonly found: boolean;
  readonly receipt: StoredReceipt | null;
}

export interface NativeStorageTransaction {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean | void>;
}
export interface NativeStorageState {
  readonly id: NativeStorageId;
  readonly storage: {
    transaction<T>(callback: (transaction: NativeStorageTransaction) => Promise<T>): Promise<T>;
  };
}
export interface NativeStorageId {
  equals(other: unknown): boolean;
  toString(): string;
}
export interface NativeStorageNamespace {
  idFromName(name: string): NativeStorageId;
  get(id: NativeStorageId): { fetch(request: Request): Promise<Response> };
}

// A wrapper supplies actual native state and namespace ports. This interface
// grants neither production qualification nor native replication evidence.
export interface NativeStorageEnvironment { readonly NATIVE_STORAGE: NativeStorageNamespace }
