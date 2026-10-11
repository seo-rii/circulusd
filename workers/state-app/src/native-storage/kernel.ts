import { digestBytes, type Digest } from "@circulusd/protocol-types";
import {
  EMPTY_DIGEST, bytes, decodeWire, encodeWire, identifier, parseBarrierRequest,
  parseCommitRequest, parseReceiptRequest, record, revision, snapshotRef, storedReceipt,
  validateStateDigest,
} from "./codec.ts";
import {
  MAXIMUM_REVISION, NativeStorageError, resolveNativeStorageBounds,
  type BarrierResult, type CommitResult, type NativeStorageBounds,
  type NativeStorageBoundsInput, type NativeStorageNamespace, type NativeStorageState,
  type NativeStorageTransaction, type ReceiptResult, type SnapshotRef, type StoredReceipt,
} from "./types.ts";

const PREFIX = "circulusd.native-storage.v1";
const META_KEY = `${PREFIX}.metadata`;
const CHUNK_BYTES = 1 << 20;
const RECEIPT_OVERHEAD = 32_768;
interface Metadata {
  readonly formatVersion: 1;
  readonly objectId: string;
  readonly physicalId: string;
  readonly revision: number;
  readonly stateDigest: Digest;
  readonly stateBytes: number;
  readonly stateChunks: number;
  readonly barrierSerial: number;
  readonly barrierMarker: Uint8Array;
}
interface ReceiptManifest {
  readonly commandId: string;
  readonly digest: Digest;
  readonly encodedBytes: number;
  readonly chunks: number;
}

export function nativeStorageObjectName(objectId: string): string {
  return JSON.stringify(["circulusd.native-storage.cell", 1, identifier(objectId)]);
}
function corrupt(): never { throw new NativeStorageError("CORRUPT_STATE"); }
function sameRef(left: SnapshotRef, right: SnapshotRef): boolean {
  return left.objectId === right.objectId && left.exists === right.exists &&
    left.revision === right.revision && left.stateDigest === right.stateDigest;
}
function ref(objectId: string, metadata: Metadata | undefined): SnapshotRef {
  return { objectId, exists: metadata !== undefined, revision: metadata?.revision ?? 0,
    stateDigest: metadata?.stateDigest ?? EMPTY_DIGEST };
}
function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  for (let i = 0; i < left.byteLength; i++) if (left[i] !== right[i]) return false;
  return true;
}

// This kernel only stages/commits native DO storage. The deployment's DO fetch
// output gate, active replicator and independent native qualification must hold
// its reply. This class cannot observe or certify that external native gate.
export class NativeStorageKernel {
  private readonly bounds: NativeStorageBounds;
  constructor(private readonly state: NativeStorageState, private readonly namespace: NativeStorageNamespace,
    bounds: NativeStorageBoundsInput = {}) {
    this.bounds = resolveNativeStorageBounds(bounds);
    if (!state?.id || typeof state.id.equals !== "function" || typeof state.id.toString !== "function" ||
        typeof state.storage?.transaction !== "function" || typeof namespace?.idFromName !== "function") {
      throw new NativeStorageError("INVALID_ARGUMENT");
    }
  }
  private route(objectId: string): string {
    const expected = this.namespace.idFromName(nativeStorageObjectName(objectId));
    if (!this.state.id.equals(expected)) throw new NativeStorageError("INVALID_ARGUMENT");
    return identifier(this.state.id.toString());
  }
  private async metadata(tx: NativeStorageTransaction, objectId: string, physicalId: string): Promise<Metadata | undefined> {
    const encoded = await tx.get<unknown>(META_KEY);
    if (encoded === undefined) return undefined;
    try {
      const value = record(decodeWire(bytes(encoded, 4096)), ["formatVersion", "objectId", "physicalId", "revision",
        "stateDigest", "stateBytes", "stateChunks", "barrierSerial", "barrierMarker"]);
      const current = snapshotRef({ objectId: value.objectId, exists: true, revision: value.revision, stateDigest: value.stateDigest });
      const stateBytes = revision(value.stateBytes), stateChunks = revision(value.stateChunks);
      const barrierSerial = revision(value.barrierSerial);
      const barrierMarker = bytes(value.barrierMarker, 32);
      if (value.formatVersion !== 1 || current.objectId !== objectId || value.physicalId !== physicalId ||
          stateBytes > this.bounds.maxStateBytes || stateChunks !== Math.ceil(stateBytes / CHUNK_BYTES) ||
          (barrierSerial === 0 ? barrierMarker.byteLength !== 0 : barrierMarker.byteLength !== 32)) corrupt();
      return { formatVersion: 1, objectId, physicalId, revision: current.revision, stateDigest: current.stateDigest,
        stateBytes, stateChunks, barrierSerial, barrierMarker };
    } catch { return corrupt(); }
  }
  private async readChunks(tx: NativeStorageTransaction, prefix: string, count: number, length: number): Promise<Uint8Array> {
    const result = new Uint8Array(length);
    for (let index = 0; index < count; index++) {
      const value = await tx.get<unknown>(`${prefix}.${index}`);
      if (!(value instanceof Uint8Array) || value.byteLength !== Math.min(CHUNK_BYTES, length - index * CHUNK_BYTES)) corrupt();
      result.set(value, index * CHUNK_BYTES);
    }
    return result;
  }
  private async stateBytes(tx: NativeStorageTransaction, metadata: Metadata | undefined): Promise<Uint8Array> {
    if (metadata === undefined) return new Uint8Array();
    const value = await this.readChunks(tx, `${PREFIX}.state`, metadata.stateChunks, metadata.stateBytes);
    try { await validateStateDigest(value, metadata.stateDigest); } catch { corrupt(); }
    return value;
  }
  private async receiptPrefix(commandId: string): Promise<string> {
    return `${PREFIX}.receipt.${await digestBytes(new TextEncoder().encode(commandId))}`;
  }
  private receiptLimit(): number {
    return Math.min(this.bounds.maxTransactionBytes,
      this.bounds.maxReceiptResponseBytes + this.bounds.maxCapabilityClaimBytes + RECEIPT_OVERHEAD);
  }
  private async readReceipt(tx: NativeStorageTransaction, commandId: string, anchored: boolean): Promise<StoredReceipt | undefined> {
    const prefix = await this.receiptPrefix(commandId);
    const raw = await tx.get<unknown>(`${prefix}.manifest`);
    if (raw === undefined) return undefined;
    // An atomic receipt commit always creates the object's physical metadata
    // anchor. Do not recover or promote copied/orphan receipts without it.
    if (!anchored) corrupt();
    try {
      const value = record(decodeWire(bytes(raw, 4096)), ["commandId", "digest", "encodedBytes", "chunks"]);
      if (value.commandId !== commandId) corrupt();
      const encodedBytes = revision(value.encodedBytes, 1), chunks = revision(value.chunks, 1);
      if (encodedBytes > this.receiptLimit() || chunks !== Math.ceil(encodedBytes / CHUNK_BYTES)) corrupt();
      const payload = await this.readChunks(tx, prefix, chunks, encodedBytes);
      if (await digestBytes(payload) !== value.digest) corrupt();
      return storedReceipt(decodeWire(payload, this.bounds), this.bounds);
    } catch { return corrupt(); }
  }
  private async writeChunks(tx: NativeStorageTransaction, prefix: string, value: Uint8Array): Promise<void> {
    for (let offset = 0; offset < value.byteLength; offset += CHUNK_BYTES) {
      await tx.put(`${prefix}.${offset / CHUNK_BYTES}`, value.slice(offset, offset + CHUNK_BYTES));
    }
  }
  private async transaction<T>(objectId: string, callback: (tx: NativeStorageTransaction, metadata: Metadata | undefined,
    physicalId: string) => Promise<T>): Promise<T> {
    const physicalId = this.route(objectId);
    return this.state.storage.transaction(async (tx) => {
      const metadata = await this.metadata(tx, objectId, physicalId);
      return callback(tx, metadata, physicalId);
    });
  }
  async readSnapshot(value: unknown): Promise<{ readonly snapshot: SnapshotRef; readonly state: Uint8Array }> {
    const input = record(value, ["objectId"]), objectId = identifier(input.objectId);
    return this.transaction(objectId, async (tx, metadata) => ({ snapshot: ref(objectId, metadata), state: await this.stateBytes(tx, metadata) }));
  }
  async lookupReceipt(value: unknown): Promise<ReceiptResult> {
    const input = parseReceiptRequest(value);
    return this.transaction(input.snapshot.objectId, async (tx, metadata) => {
      const current = ref(input.snapshot.objectId, metadata);
      if (!sameRef(current, input.snapshot)) throw new NativeStorageError("SNAPSHOT_CONFLICT");
      const receipt = await this.readReceipt(tx, input.commandId, metadata !== undefined);
      return { snapshot: current, commandId: input.commandId, found: receipt !== undefined, receipt: receipt ?? null };
    });
  }
  async compareAndCommit(value: unknown): Promise<CommitResult> {
    const input = await parseCommitRequest(value, this.bounds);
    return this.transaction(input.snapshot.objectId, async (tx, metadata, physicalId) => {
      const current = ref(input.snapshot.objectId, metadata);
      if (!sameRef(current, input.snapshot)) throw new NativeStorageError("SNAPSHOT_CONFLICT");
      // Complete all corruption and immutable-receipt checks before any put.
      const oldState = await this.stateBytes(tx, metadata);
      const pending: { prefix: string; payload: Uint8Array; manifest: ReceiptManifest }[] = [];
      for (const write of input.receipts) {
        const existing = await this.readReceipt(tx, write.commandId, metadata !== undefined);
        const payload = encodeWire(write.receipt, this.bounds);
        if (existing !== undefined) {
          if (!equalBytes(encodeWire(existing, this.bounds), payload)) throw new NativeStorageError("RECEIPT_CONFLICT");
          continue;
        }
        pending.push({ prefix: await this.receiptPrefix(write.commandId), payload,
          manifest: { commandId: write.commandId, digest: await digestBytes(payload), encodedBytes: payload.byteLength,
            chunks: Math.ceil(payload.byteLength / CHUNK_BYTES) } });
      }
      const nextState = input.stateWritten ? input.state : oldState;
      const stateDigest = input.stateWritten ? await digestBytes(nextState) : current.stateDigest;
      const next: Metadata = { formatVersion: 1, objectId: current.objectId, physicalId, revision: current.revision + 1,
        stateDigest, stateBytes: nextState.byteLength, stateChunks: Math.ceil(nextState.byteLength / CHUNK_BYTES),
        barrierSerial: metadata?.barrierSerial ?? 0, barrierMarker: metadata?.barrierMarker ?? new Uint8Array() };
      if (input.stateWritten) {
        await this.writeChunks(tx, `${PREFIX}.state`, nextState);
        for (let index = next.stateChunks; index < (metadata?.stateChunks ?? 0); index++) await tx.delete(`${PREFIX}.state.${index}`);
      }
      for (const write of pending) {
        await this.writeChunks(tx, write.prefix, write.payload);
        await tx.put(`${write.prefix}.manifest`, encodeWire(write.manifest, this.bounds));
      }
      // This metadata put is mandatory even for a read-only Go callback. It
      // advances the logical revision and produces a real native SQLite write.
      await tx.put(META_KEY, encodeWire(next, this.bounds));
      return { snapshot: ref(current.objectId, next), requestDigest: input.requestDigest,
        token: { objectId: current.objectId, revision: next.revision } };
    });
  }
  async confirmBarrier(value: unknown): Promise<BarrierResult> {
    const input = parseBarrierRequest(value);
    return this.transaction(input.token.objectId, async (tx, metadata) => {
      if (metadata === undefined || metadata.revision < input.token.revision) throw new NativeStorageError("INVALID_ARGUMENT");
      if (metadata.barrierSerial === MAXIMUM_REVISION) throw new NativeStorageError("UNAVAILABLE");
      const barrierSerial = metadata.barrierSerial + 1;
      // Repeated markers still change serial. Never shortcut to a cached read
      // response: only a fresh physical write forces native durability proof.
      await tx.put(META_KEY, encodeWire({ ...metadata, barrierSerial, barrierMarker: input.marker }, this.bounds));
      return { token: input.token, marker: input.marker, observedRevision: metadata.revision, barrierSerial };
    });
  }
}
