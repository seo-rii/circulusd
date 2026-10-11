import { digestBytes, encodeCanonicalCbor } from "@circulusd/protocol-types";
import {
  KEY_HEADER, SIGNATURE_HEADER, STORAGE_PROTOCOL, STORAGE_SCHEMA, TRANSACTION_PATH, TRANSACTION_TYPE,
  commitDigest, storageDirectionalKeys, storageRequestMac, type StorageOperation,
} from "../../src/native-storage/codec.ts";
import { nativeStorageObjectName } from "../../src/native-storage/kernel.ts";
import type {
  CommitRequest, NativeStorageId, NativeStorageNamespace, NativeStorageState, NativeStorageTransaction,
  SnapshotRef, StoredReceipt,
} from "../../src/native-storage/types.ts";

export const NOW = 1_788_888_888_000;
export const OBJECT_ID = "tenant:one/session:storage";
export const REQUEST_ID = "req_AAAAAAAAAAAAAAAAAAAAAAAAAA";
export const ROOT_KEY = new Uint8Array(32).fill(37);
export const KEY_ID = "native-storage-test";
export function deferred<T = void>(): { promise: Promise<T>; resolve(value: T): void; reject(error: unknown): void } {
  let resolve!: (value: T) => void, reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
export class StorageFixture {
  values = new Map<string, unknown>();
  calls = 0;
  mutations = 0;
  failPutAt = 0;
  private tail: Promise<void> = Promise.resolve();
  async transaction<T>(callback: (tx: NativeStorageTransaction) => Promise<T>): Promise<T> {
    const previous = this.tail, next = deferred();
    this.tail = next.promise;
    await previous;
    this.calls++;
    const staged = structuredClone(this.values);
    let puts = 0, mutations = 0;
    try {
      const tx: NativeStorageTransaction = {
        get: async <Value>(key: string) => structuredClone(staged.get(key)) as Value | undefined,
        put: async (key, value) => {
          if (encodeCanonicalCbor(value).byteLength > 2_000_000) throw new Error("fixture KV value too large");
          puts++;
          if (this.failPutAt !== 0 && puts === this.failPutAt) throw new Error("private storage failure");
          staged.set(key, structuredClone(value)); mutations++;
        },
        delete: async (key) => { mutations++; return staged.delete(key); },
      };
      const result = await callback(tx);
      this.values = staged; this.mutations += mutations;
      return result;
    } finally { next.resolve(); }
  }
}
class FixtureId implements NativeStorageId {
  constructor(readonly name: string) {}
  equals(other: unknown): boolean { return other instanceof FixtureId && other.name === this.name; }
  toString(): string { return `physical:${this.name.length}:${this.name.slice(-80)}`; }
}
export class NamespaceFixture implements NativeStorageNamespace {
  calls = 0;
  lastName = "";
  fetcher: ((id: NativeStorageId, request: Request) => Promise<Response>) | undefined;
  idFromName(name: string): NativeStorageId { this.lastName = name; return new FixtureId(name); }
  get(id: NativeStorageId): { fetch(request: Request): Promise<Response> } {
    return { fetch: async (request) => { this.calls++; if (!this.fetcher) throw new Error("fixture source unavailable"); return this.fetcher(id, request); } };
  }
  state(storage: StorageFixture, objectId = OBJECT_ID): NativeStorageState {
    return { storage, id: this.idFromName(nativeStorageObjectName(objectId)) };
  }
}
export async function makeCommit(snapshot: SnapshotRef, state: Uint8Array = new Uint8Array(),
  receipts: CommitRequest["receipts"] = [], stateWritten = true): Promise<CommitRequest> {
  const body = { snapshot: structuredClone(snapshot), stateWritten, state: Uint8Array.from(state),
    receipts: receipts.map((write) => ({ commandId: write.commandId, receipt: structuredClone(write.receipt) })) };
  return { ...body, requestDigest: await commitDigest(body) };
}
export async function makeReceipt(response = new Uint8Array([17])): Promise<StoredReceipt> {
  return { commandDigest: await digestBytes(new Uint8Array([42])), response,
    capabilityClaims: [{ kind: "model-dispatch", payload: new Uint8Array([8, 9]) }] };
}
export function wireEnvelope(operation: StorageOperation, body: unknown): Record<string, unknown> {
  return { protocol: STORAGE_PROTOCOL, major: 1, minor: 0, schemaDigest: STORAGE_SCHEMA,
    requestId: REQUEST_ID, sentAtUnixMs: NOW, operation, body };
}
export async function authenticatedRequest(value: unknown, rootKey = ROOT_KEY): Promise<Request> {
  const body = encodeCanonicalCbor(value), keys = await storageDirectionalKeys(rootKey);
  return new Request(`http://native.local${TRANSACTION_PATH}`, { method: "POST", body,
    headers: { "content-type": TRANSACTION_TYPE, [KEY_HEADER]: KEY_ID,
      [SIGNATURE_HEADER]: await storageRequestMac(keys.request, KEY_ID, body) } });
}
