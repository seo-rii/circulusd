import {
  decodeCanonicalCbor,
  digestBytes,
  encodeCanonicalCbor,
  isDigest,
  type Digest,
} from "@circulusd/protocol-types";

import {
  HostContractError,
  type AggregateMigrationResult,
  type CellRoutePort,
  type TransactionPort,
} from "./contracts.ts";

const MANIFEST_KEY = "circulusd.state-app.aggregate.v2.manifest";
const ANCHOR_KEY = "circulusd.state-app.aggregate.v2.anchor";
const CHUNK_KEY_PREFIX = "circulusd.state-app.aggregate.v2.chunk";
// Externalized payload blobs (storage redesign stage B) are content-addressed by
// their digest and framed into the same 1 MiB physical chunks as the state record.
const BLOB_CHUNK_KEY_PREFIX = "circulusd.state-app.aggregate.v2.blob";
const RECORD_FORMAT_VERSION = 2 as const;
const CHUNK_BYTES = 1_048_576;
// A stored record is simultaneously encoded, decoded, normalized, validated,
// and cloned on command paths. Keep each copy below 4 MiB so the worst-case
// amplification remains bounded inside workerd's 128 MiB isolate limit.
// Exported so the Session aggregate's state budget (session/types.ts) can be
// asserted to stay strictly inside these host record limits (review U04): the
// aggregate must never produce a state whose stored record the host then rejects.
export const MAX_RECORD_BYTES = 4 * 1_048_576;
export const MAX_RECORD_ITEMS = 100_000;
export const MAX_RECORD_DEPTH = 72;
// A single externalized blob holds one payload (a checkpoint's bytes, ≤ 4 MiB, or a
// bounded protocol value, ≤ 1 MiB), so it fits the same record-byte ceiling.
export const MAX_BLOB_BYTES = MAX_RECORD_BYTES;
const MAX_CHUNKS = Math.ceil(MAX_RECORD_BYTES / CHUNK_BYTES);
const MAX_BLOB_CHUNKS = Math.ceil(MAX_BLOB_BYTES / CHUNK_BYTES);
const MAX_TRANSACTION_MUTATED_KEYS = 128;
const MAX_CELL_NAME_BYTES = 2_048;
const MAX_PHYSICAL_ID_BYTES = 256;
const MANIFEST_REQUIRED_KEYS = [
  "aggregateKind",
  "cellName",
  "chunkCount",
  "encodedBytes",
  "formatVersion",
  "generationDigest",
  "initializationDigest",
  "physicalCellId",
] as const;
const textEncoder = new TextEncoder();

export interface StateRecord<State> {
  readonly formatVersion: typeof RECORD_FORMAT_VERSION;
  readonly aggregateKind: string;
  readonly initializationDigest: Digest;
  readonly cellName: string | null;
  readonly physicalCellId: string | null;
  readonly state: State;
}

// A blob the current state references: its content digest (also its chunk-key
// prefix) and its exact byte length, from which the chunk count is derived.
interface BlobRecordRef {
  readonly digest: Digest;
  readonly encodedBytes: number;
}

interface StateManifest {
  readonly formatVersion: typeof RECORD_FORMAT_VERSION;
  readonly aggregateKind: string;
  readonly initializationDigest: Digest;
  readonly cellName: string | null;
  readonly physicalCellId: string | null;
  readonly generationDigest: Digest;
  readonly chunkCount: number;
  readonly encodedBytes: number;
  // The complete set of externalized blob digests the stored state references.
  // Absent in legacy manifests written before stage B; read as an empty set.
  readonly referencedBlobs: readonly BlobRecordRef[];
}

interface StateAnchor {
  readonly formatVersion: typeof RECORD_FORMAT_VERSION;
  readonly aggregateKind: string;
  readonly initializationDigest: Digest;
  readonly cellName: string | null;
  readonly physicalCellId: string | null;
}

export interface StoredStateRecord<State> {
  readonly record: StateRecord<State>;
  readonly manifest: StateManifest;
}

function chunkKey(generationDigest: Digest, index: number): string {
  return `${CHUNK_KEY_PREFIX}.${generationDigest}.${index.toString().padStart(3, "0")}`;
}

function blobChunkKey(digest: Digest, index: number): string {
  return `${BLOB_CHUNK_KEY_PREFIX}.${digest}.${index.toString().padStart(3, "0")}`;
}

// Parse a manifest's optional referencedBlobs field. Legacy manifests (pre stage B)
// omit it and reference no blobs, so absence is an empty set. Each entry must carry
// a valid digest and a plausible byte length, and digests must be unique.
function parseReferencedBlobs(value: unknown): BlobRecordRef[] {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new HostContractError("CORRUPT_STATE", "stored manifest referencedBlobs is invalid");
  }
  const refs: BlobRecordRef[] = [];
  const seen = new Set<string>();
  for (const entry of value) {
    if (
      typeof entry !== "object" ||
      entry === null ||
      Array.isArray(entry) ||
      Reflect.ownKeys(entry).length !== 2 ||
      !Object.prototype.hasOwnProperty.call(entry, "digest") ||
      !Object.prototype.hasOwnProperty.call(entry, "encodedBytes")
    ) {
      throw new HostContractError("CORRUPT_STATE", "stored manifest blob reference is invalid");
    }
    const { digest, encodedBytes } = entry as { digest: unknown; encodedBytes: unknown };
    if (
      !isDigest(digest) ||
      typeof encodedBytes !== "number" ||
      !Number.isSafeInteger(encodedBytes) ||
      encodedBytes < 1 ||
      encodedBytes > MAX_BLOB_BYTES ||
      seen.has(digest)
    ) {
      throw new HostContractError("CORRUPT_STATE", "stored manifest blob reference is invalid");
    }
    seen.add(digest);
    refs.push({ digest, encodedBytes });
  }
  return refs;
}

// Validate a stored manifest's shape while tolerating the optional referencedBlobs
// key (absent in legacy manifests). All scalar fields are required; the only
// permitted extra key is referencedBlobs.
function manifestRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new HostContractError("CORRUPT_STATE", "stored manifest is not an object");
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) {
    throw new HostContractError("CORRUPT_STATE", "stored manifest shape is invalid");
  }
  for (const key of MANIFEST_REQUIRED_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) {
      throw new HostContractError("CORRUPT_STATE", "stored manifest shape is invalid");
    }
  }
  for (const key of keys as string[]) {
    if (
      key !== "referencedBlobs" &&
      !(MANIFEST_REQUIRED_KEYS as readonly string[]).includes(key)
    ) {
      throw new HostContractError("CORRUPT_STATE", "stored manifest shape is invalid");
    }
  }
  return value as Record<string, unknown>;
}

function exactRecord(value: unknown, expectedKeys: readonly string[], label: string) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new HostContractError("CORRUPT_STATE", `${label} is not an object`);
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.some((key) => typeof key !== "string") ||
    keys.length !== expectedKeys.length ||
    expectedKeys.some((key) => !Object.prototype.hasOwnProperty.call(value, key))
  ) {
    throw new HostContractError("CORRUPT_STATE", `${label} shape is invalid`);
  }
  return value as Record<string, unknown>;
}

export class ChunkedAggregateStorage<State> {
  readonly #aggregateKind: string;
  readonly #validateState: (state: State) => void | Promise<void>;
  readonly #migrateState:
    | ((state: unknown) =>
        AggregateMigrationResult<State> | Promise<AggregateMigrationResult<State>>)
    | undefined;
  readonly #route: CellRoutePort | undefined;

  constructor(
    aggregateKind: string,
    validateState: (state: State) => void | Promise<void>,
    route?: CellRoutePort,
    migrateState?: (
      state: unknown,
    ) => AggregateMigrationResult<State> | Promise<AggregateMigrationResult<State>>,
  ) {
    this.#aggregateKind = aggregateKind;
    this.#validateState = validateState;
    this.#route = route;
    this.#migrateState = migrateState;
  }

  buildInitialRecord(
    initializationDigest: Digest,
    state: State,
    cellName?: string,
  ): StateRecord<State> {
    let stateSnapshot: State;
    try {
      stateSnapshot = structuredClone(state);
    } catch (error) {
      throw new HostContractError(
        "STRUCTURED_CLONE_FAILED",
        "initial aggregate state is not structured-cloneable",
        { cause: error },
      );
    }
    if (this.#route === undefined) {
      if (cellName !== undefined) {
        throw new HostContractError(
          "CELL_ID_MISMATCH",
          "a logical cell name requires a physical cell route",
        );
      }
      return {
        formatVersion: RECORD_FORMAT_VERSION,
        aggregateKind: this.#aggregateKind,
        initializationDigest,
        cellName: null,
        physicalCellId: null,
        state: stateSnapshot,
      };
    }
    if (typeof cellName !== "string" || cellName.length === 0) {
      throw new HostContractError(
        "CELL_ID_MISMATCH",
        "routed aggregate initialization requires a logical cell name",
      );
    }
    const physicalCellId = this.#assertRoute(cellName);
    return {
      formatVersion: RECORD_FORMAT_VERSION,
      aggregateKind: this.#aggregateKind,
      initializationDigest,
      cellName,
      physicalCellId,
      state: stateSnapshot,
    };
  }

  async read(transaction: TransactionPort): Promise<StoredStateRecord<State> | undefined> {
    const storedManifest = await transaction.get<unknown>(MANIFEST_KEY);
    const storedAnchor = await transaction.get<unknown>(ANCHOR_KEY);
    if (storedManifest === undefined && storedAnchor === undefined) {
      return undefined;
    }
    if (storedManifest === undefined || storedAnchor === undefined) {
      throw new HostContractError(
        "CORRUPT_STATE",
        "stored aggregate durable header is incomplete",
      );
    }
    let manifestSnapshot: unknown;
    let anchorSnapshot: unknown;
    try {
      manifestSnapshot = structuredClone(storedManifest);
      anchorSnapshot = structuredClone(storedAnchor);
    } catch (error) {
      throw new HostContractError("CORRUPT_STATE", "stored header cannot be cloned", {
        cause: error,
      });
    }
    const anchorCandidate = exactRecord(
      anchorSnapshot,
      [
        "aggregateKind",
        "cellName",
        "formatVersion",
        "initializationDigest",
        "physicalCellId",
      ],
      "stored anchor",
    );
    if (
      anchorCandidate.formatVersion !== RECORD_FORMAT_VERSION ||
      anchorCandidate.aggregateKind !== this.#aggregateKind ||
      !isDigest(anchorCandidate.initializationDigest) ||
      !this.#validRouteMetadata(
        anchorCandidate.cellName,
        anchorCandidate.physicalCellId,
      )
    ) {
      throw new HostContractError("CORRUPT_STATE", "stored anchor metadata is invalid");
    }
    const anchor = anchorCandidate as unknown as StateAnchor;
    const candidate = manifestRecord(manifestSnapshot);
    if (
      candidate.formatVersion !== RECORD_FORMAT_VERSION ||
      candidate.aggregateKind !== this.#aggregateKind ||
      !isDigest(candidate.initializationDigest) ||
      !isDigest(candidate.generationDigest) ||
      !Number.isSafeInteger(candidate.chunkCount) ||
      typeof candidate.chunkCount !== "number" ||
      candidate.chunkCount < 1 ||
      candidate.chunkCount > MAX_CHUNKS ||
      !Number.isSafeInteger(candidate.encodedBytes) ||
      typeof candidate.encodedBytes !== "number" ||
      candidate.encodedBytes < 1 ||
      candidate.encodedBytes > MAX_RECORD_BYTES ||
      candidate.chunkCount !== Math.ceil(candidate.encodedBytes / CHUNK_BYTES) ||
      !this.#validRouteMetadata(candidate.cellName, candidate.physicalCellId)
    ) {
      throw new HostContractError("CORRUPT_STATE", "stored manifest metadata is invalid");
    }
    const manifest: StateManifest = {
      formatVersion: RECORD_FORMAT_VERSION,
      aggregateKind: candidate.aggregateKind as string,
      initializationDigest: candidate.initializationDigest as Digest,
      cellName: candidate.cellName as string | null,
      physicalCellId: candidate.physicalCellId as string | null,
      generationDigest: candidate.generationDigest as Digest,
      chunkCount: candidate.chunkCount,
      encodedBytes: candidate.encodedBytes,
      referencedBlobs: parseReferencedBlobs(candidate.referencedBlobs),
    };
    if (
      manifest.initializationDigest !== anchor.initializationDigest ||
      manifest.cellName !== anchor.cellName ||
      manifest.physicalCellId !== anchor.physicalCellId
    ) {
      throw new HostContractError(
        "CORRUPT_STATE",
        "stored aggregate headers disagree",
      );
    }
    const encoded = new Uint8Array(manifest.encodedBytes);
    let offset = 0;
    for (let index = 0; index < manifest.chunkCount; index += 1) {
      const storedChunk = await transaction.get<unknown>(
        chunkKey(manifest.generationDigest, index),
      );
      if (
        !(storedChunk instanceof Uint8Array) ||
        Object.getPrototypeOf(storedChunk) !== Uint8Array.prototype ||
        !(storedChunk.buffer instanceof ArrayBuffer) ||
        Object.getPrototypeOf(storedChunk.buffer) !== ArrayBuffer.prototype ||
        storedChunk.byteOffset !== 0 ||
        storedChunk.byteLength !== storedChunk.buffer.byteLength
      ) {
        throw new HostContractError("CORRUPT_STATE", "stored aggregate chunk is invalid");
      }
      const expectedLength = Math.min(CHUNK_BYTES, manifest.encodedBytes - offset);
      if (storedChunk.byteLength !== expectedLength) {
        throw new HostContractError(
          "CORRUPT_STATE",
          "stored aggregate chunk length is invalid",
        );
      }
      encoded.set(storedChunk, offset);
      offset += storedChunk.byteLength;
    }
    let actualDigest: Digest;
    try {
      actualDigest = await digestBytes(encoded);
    } catch (error) {
      throw new HostContractError("CORRUPT_STATE", "stored aggregate cannot be digested", {
        cause: error,
      });
    }
    if (actualDigest !== manifest.generationDigest) {
      throw new HostContractError("CORRUPT_STATE", "stored aggregate digest is invalid");
    }

    let decoded: unknown;
    try {
      decoded = decodeCanonicalCbor(encoded, {
        maxBytes: MAX_RECORD_BYTES,
        maxDepth: MAX_RECORD_DEPTH,
        maxItems: MAX_RECORD_ITEMS,
      });
    } catch (error) {
      throw new HostContractError("CORRUPT_STATE", "stored aggregate encoding is invalid", {
        cause: error,
      });
    }
    const recordCandidate = exactRecord(
      decoded,
      [
        "aggregateKind",
        "cellName",
        "formatVersion",
        "initializationDigest",
        "physicalCellId",
        "state",
      ],
      "stored aggregate record",
    );
    if (
      recordCandidate.formatVersion !== RECORD_FORMAT_VERSION ||
      recordCandidate.aggregateKind !== this.#aggregateKind ||
      recordCandidate.initializationDigest !== manifest.initializationDigest ||
      recordCandidate.cellName !== manifest.cellName ||
      recordCandidate.physicalCellId !== manifest.physicalCellId ||
      !Object.prototype.hasOwnProperty.call(recordCandidate, "state")
    ) {
      throw new HostContractError("CORRUPT_STATE", "stored aggregate metadata is invalid");
    }
    const storedRecord = recordCandidate as unknown as StateRecord<unknown>;
    this.#assertStoredRoute(storedRecord as StateRecord<State>);
    let record: StateRecord<State>;
    let migrated = false;
    // A migration may externalize payloads it lifts out of a legacy inline state
    // (storage redesign stage B); its blob effects are persisted by the migrating
    // rewrite below, using the same mechanism as a normal command write.
    let migrationBlobs: ReadonlyMap<Digest, Uint8Array> | undefined;
    let migrationReferencedBlobs: readonly Digest[] | undefined;
    try {
      let state = storedRecord.state as State;
      if (this.#migrateState !== undefined) {
        const migration = await this.#migrateState(storedRecord.state);
        if (
          typeof migration !== "object" ||
          migration === null ||
          Array.isArray(migration) ||
          typeof migration.migrated !== "boolean" ||
          !Object.prototype.hasOwnProperty.call(migration, "state") ||
          Reflect.ownKeys(migration).some(
            (key) =>
              key !== "state" &&
              key !== "migrated" &&
              key !== "blobs" &&
              key !== "referencedBlobs",
          )
        ) {
          throw new TypeError("aggregate migration returned an invalid result");
        }
        state = migration.state;
        migrated = migration.migrated;
        migrationBlobs = migration.blobs;
        migrationReferencedBlobs = migration.referencedBlobs;
      }
      record = {
        ...storedRecord,
        state,
      } as StateRecord<State>;
      await this.#validateState(record.state);
    } catch (error) {
      throw new HostContractError("CORRUPT_STATE", "stored aggregate state is invalid", {
        cause: error,
      });
    }
    if (!migrated) {
      return { record, manifest };
    }
    const migratedManifest = await this.#writeRecord(
      transaction,
      record,
      manifest,
      migrationBlobs,
      migrationReferencedBlobs,
    );
    return { record, manifest: migratedManifest };
  }

  async write(
    transaction: TransactionPort,
    record: StateRecord<State>,
    previousManifest?: StateManifest,
    blobs?: ReadonlyMap<Digest, Uint8Array>,
    referencedBlobs?: readonly Digest[],
  ): Promise<void> {
    await this.#writeRecord(transaction, record, previousManifest, blobs, referencedBlobs);
  }

  // Read one externalized blob by its content digest. Returns undefined when the
  // current state does not reference that digest. The reassembled bytes are
  // re-digested against the requested digest before returning, so a corrupt or
  // truncated chunk fails closed rather than yielding wrong content.
  async readBlob(
    transaction: TransactionPort,
    digest: Digest,
  ): Promise<Uint8Array | undefined> {
    if (!isDigest(digest)) {
      throw new HostContractError("CORRUPT_STATE", "requested blob digest is invalid");
    }
    const storedManifest = await transaction.get<unknown>(MANIFEST_KEY);
    if (storedManifest === undefined) {
      return undefined;
    }
    let manifestSnapshot: unknown;
    try {
      manifestSnapshot = structuredClone(storedManifest);
    } catch (error) {
      throw new HostContractError("CORRUPT_STATE", "stored manifest cannot be cloned", {
        cause: error,
      });
    }
    const candidate = manifestRecord(manifestSnapshot);
    const reference = parseReferencedBlobs(candidate.referencedBlobs).find(
      (entry) => entry.digest === digest,
    );
    if (reference === undefined) {
      return undefined;
    }
    const bytes = await this.#readChunkedBytes(
      transaction,
      (index) => blobChunkKey(digest, index),
      reference.encodedBytes,
      "stored blob",
    );
    let actualDigest: Digest;
    try {
      actualDigest = await digestBytes(bytes);
    } catch (error) {
      throw new HostContractError("CORRUPT_STATE", "stored blob cannot be digested", {
        cause: error,
      });
    }
    if (actualDigest !== digest) {
      throw new HostContractError("CORRUPT_STATE", "stored blob digest is invalid");
    }
    return bytes;
  }

  async #readChunkedBytes(
    transaction: TransactionPort,
    keyFor: (index: number) => string,
    encodedBytes: number,
    label: string,
  ): Promise<Uint8Array> {
    const chunkCount = Math.ceil(encodedBytes / CHUNK_BYTES);
    const bytes = new Uint8Array(encodedBytes);
    let offset = 0;
    for (let index = 0; index < chunkCount; index += 1) {
      const storedChunk = await transaction.get<unknown>(keyFor(index));
      if (
        !(storedChunk instanceof Uint8Array) ||
        Object.getPrototypeOf(storedChunk) !== Uint8Array.prototype ||
        !(storedChunk.buffer instanceof ArrayBuffer) ||
        Object.getPrototypeOf(storedChunk.buffer) !== ArrayBuffer.prototype ||
        storedChunk.byteOffset !== 0 ||
        storedChunk.byteLength !== storedChunk.buffer.byteLength
      ) {
        throw new HostContractError("CORRUPT_STATE", `${label} chunk is invalid`);
      }
      const expectedLength = Math.min(CHUNK_BYTES, encodedBytes - offset);
      if (storedChunk.byteLength !== expectedLength) {
        throw new HostContractError("CORRUPT_STATE", `${label} chunk length is invalid`);
      }
      bytes.set(storedChunk, offset);
      offset += storedChunk.byteLength;
    }
    return bytes;
  }

  async #writeRecord(
    transaction: TransactionPort,
    record: StateRecord<State>,
    previousManifest?: StateManifest,
    blobs?: ReadonlyMap<Digest, Uint8Array>,
    referencedBlobs?: readonly Digest[],
  ): Promise<StateManifest> {
    exactRecord(
      record,
      [
        "aggregateKind",
        "cellName",
        "formatVersion",
        "initializationDigest",
        "physicalCellId",
        "state",
      ],
      "aggregate output record",
    );
    let encoded: Uint8Array;
    let generationDigest: Digest;
    try {
      encoded = encodeCanonicalCbor(record, {
        maxBytes: MAX_RECORD_BYTES,
        maxDepth: MAX_RECORD_DEPTH,
        maxItems: MAX_RECORD_ITEMS,
      });
      generationDigest = await digestBytes(encoded);
    } catch (error) {
      throw new HostContractError(
        "INVALID_AGGREGATE_OUTPUT",
        `aggregate record exceeds the ${MAX_RECORD_BYTES}-byte host limit or is not canonical`,
        { cause: error },
      );
    }
    const { referencedEntries, blobsToCreate, blobsToDelete } = await this.#resolveBlobMutations(
      previousManifest,
      blobs ?? new Map<Digest, Uint8Array>(),
      referencedBlobs ?? [],
    );
    const chunkCount = Math.ceil(encoded.byteLength / CHUNK_BYTES);
    const oldChunkMutations =
      previousManifest === undefined || previousManifest.generationDigest === generationDigest
        ? 0
        : previousManifest.chunkCount;
    const initialAnchorMutation = previousManifest === undefined ? 1 : 0;
    const createdBlobChunks = blobsToCreate.reduce((total, blob) => total + blob.chunkCount, 0);
    const deletedBlobChunks = blobsToDelete.reduce(
      (total, blob) => total + Math.ceil(blob.encodedBytes / CHUNK_BYTES),
      0,
    );
    if (
      chunkCount < 1 ||
      chunkCount > MAX_CHUNKS ||
      1 +
        initialAnchorMutation +
        chunkCount +
        oldChunkMutations +
        createdBlobChunks +
        deletedBlobChunks >
        MAX_TRANSACTION_MUTATED_KEYS
    ) {
      throw new HostContractError(
        "INVALID_AGGREGATE_OUTPUT",
        "aggregate chunk count exceeds the atomic transaction limit",
      );
    }
    for (const blob of blobsToCreate) {
      for (let index = 0; index < blob.chunkCount; index += 1) {
        const start = index * CHUNK_BYTES;
        await transaction.put(
          blobChunkKey(blob.digest, index),
          blob.bytes.slice(start, Math.min(blob.bytes.byteLength, start + CHUNK_BYTES)),
        );
      }
    }
    for (let index = 0; index < chunkCount; index += 1) {
      const start = index * CHUNK_BYTES;
      await transaction.put(
        chunkKey(generationDigest, index),
        encoded.slice(start, Math.min(encoded.byteLength, start + CHUNK_BYTES)),
      );
    }
    const manifest: StateManifest = {
      formatVersion: RECORD_FORMAT_VERSION,
      aggregateKind: this.#aggregateKind,
      initializationDigest: record.initializationDigest,
      cellName: record.cellName,
      physicalCellId: record.physicalCellId,
      generationDigest,
      chunkCount,
      encodedBytes: encoded.byteLength,
      referencedBlobs: referencedEntries,
    };
    if (previousManifest === undefined) {
      const anchor: StateAnchor = {
        formatVersion: RECORD_FORMAT_VERSION,
        aggregateKind: this.#aggregateKind,
        initializationDigest: record.initializationDigest,
        cellName: record.cellName,
        physicalCellId: record.physicalCellId,
      };
      await transaction.put(ANCHOR_KEY, anchor);
    }
    await transaction.put(MANIFEST_KEY, manifest);
    if (
      previousManifest !== undefined &&
      previousManifest.generationDigest !== generationDigest
    ) {
      for (let index = 0; index < previousManifest.chunkCount; index += 1) {
        await transaction.delete(chunkKey(previousManifest.generationDigest, index));
      }
    }
    for (const blob of blobsToDelete) {
      const blobChunks = Math.ceil(blob.encodedBytes / CHUNK_BYTES);
      for (let index = 0; index < blobChunks; index += 1) {
        await transaction.delete(blobChunkKey(blob.digest, index));
      }
    }
    return manifest;
  }

  // Reconcile the state's new blob reference set against the previously stored one.
  // There is exactly one state per cell, so set membership is the reference count:
  // a digest newly referenced must have its bytes provided now (and they must hash
  // to that digest); a digest no longer referenced is deleted; a carried-over
  // digest keeps its already-stored chunks. Content-addressing makes this idempotent
  // and lets two references to the same payload share one blob.
  async #resolveBlobMutations(
    previousManifest: StateManifest | undefined,
    provided: ReadonlyMap<Digest, Uint8Array>,
    referencedBlobs: readonly Digest[],
  ): Promise<{
    readonly referencedEntries: BlobRecordRef[];
    readonly blobsToCreate: { digest: Digest; bytes: Uint8Array; chunkCount: number }[];
    readonly blobsToDelete: BlobRecordRef[];
  }> {
    const previousEntries = new Map<Digest, BlobRecordRef>(
      (previousManifest?.referencedBlobs ?? []).map((entry) => [entry.digest, entry]),
    );
    const newReferences = new Set<Digest>();
    for (const digest of referencedBlobs) {
      if (!isDigest(digest)) {
        throw new HostContractError(
          "INVALID_AGGREGATE_OUTPUT",
          "aggregate referenced a blob with an invalid digest",
        );
      }
      newReferences.add(digest);
    }
    const referencedEntries: BlobRecordRef[] = [];
    const blobsToCreate: { digest: Digest; bytes: Uint8Array; chunkCount: number }[] = [];
    for (const digest of newReferences) {
      const carried = previousEntries.get(digest);
      if (carried !== undefined) {
        referencedEntries.push(carried);
        continue;
      }
      const bytes = provided.get(digest);
      if (bytes === undefined) {
        throw new HostContractError(
          "INVALID_AGGREGATE_OUTPUT",
          "aggregate referenced a blob whose bytes were not provided",
        );
      }
      if (
        !(bytes instanceof Uint8Array) ||
        Object.getPrototypeOf(bytes) !== Uint8Array.prototype ||
        bytes.byteLength < 1 ||
        bytes.byteLength > MAX_BLOB_BYTES
      ) {
        throw new HostContractError(
          "INVALID_AGGREGATE_OUTPUT",
          `provided blob exceeds the ${MAX_BLOB_BYTES}-byte host limit or is empty`,
        );
      }
      let actualDigest: Digest;
      try {
        actualDigest = await digestBytes(bytes);
      } catch (error) {
        throw new HostContractError(
          "INVALID_AGGREGATE_OUTPUT",
          "provided blob cannot be digested",
          { cause: error },
        );
      }
      if (actualDigest !== digest) {
        throw new HostContractError(
          "INVALID_AGGREGATE_OUTPUT",
          "provided blob digest does not match its bytes",
        );
      }
      const chunkCount = Math.ceil(bytes.byteLength / CHUNK_BYTES);
      if (chunkCount > MAX_BLOB_CHUNKS) {
        throw new HostContractError(
          "INVALID_AGGREGATE_OUTPUT",
          "provided blob exceeds the maximum blob chunk count",
        );
      }
      referencedEntries.push({ digest, encodedBytes: bytes.byteLength });
      blobsToCreate.push({ digest, bytes, chunkCount });
    }
    // Every provided blob must be newly referenced; a blob supplied for an
    // already-stored or unreferenced digest indicates an aggregate defect.
    if (provided.size !== blobsToCreate.length) {
      throw new HostContractError(
        "INVALID_AGGREGATE_OUTPUT",
        "aggregate provided a blob that is not newly referenced",
      );
    }
    const blobsToDelete: BlobRecordRef[] = [];
    for (const [digest, entry] of previousEntries) {
      if (!newReferences.has(digest)) {
        blobsToDelete.push(entry);
      }
    }
    return { referencedEntries, blobsToCreate, blobsToDelete };
  }

  #validRouteMetadata(cellName: unknown, physicalCellId: unknown): boolean {
    if (this.#route === undefined) {
      return cellName === null && physicalCellId === null;
    }
    return (
      typeof cellName === "string" &&
      cellName.length > 0 &&
      textEncoder.encode(cellName).byteLength <= MAX_CELL_NAME_BYTES &&
      typeof physicalCellId === "string" &&
      physicalCellId.length > 0 &&
      textEncoder.encode(physicalCellId).byteLength <= MAX_PHYSICAL_ID_BYTES
    );
  }

  #assertStoredRoute(record: StateRecord<State>): void {
    if (!this.#validRouteMetadata(record.cellName, record.physicalCellId)) {
      throw new HostContractError("CORRUPT_STATE", "stored cell route is invalid");
    }
    if (this.#route !== undefined) {
      const currentPhysicalId = this.#assertRoute(record.cellName!);
      if (currentPhysicalId !== record.physicalCellId) {
        throw new HostContractError(
          "CELL_ID_MISMATCH",
          "stored aggregate is bound to a different physical cell",
        );
      }
    }
  }

  #assertRoute(cellName: string): string {
    if (
      textEncoder.encode(cellName).byteLength > MAX_CELL_NAME_BYTES ||
      this.#route === undefined
    ) {
      throw new HostContractError("CELL_ID_MISMATCH", "logical cell name is invalid");
    }
    let physicalCellId: string;
    try {
      const expected = this.#route.namespace.idFromName(cellName);
      if (!this.#route.currentId.equals(expected)) {
        throw new Error("physical Durable Object ID differs from the routed ID");
      }
      physicalCellId = this.#route.currentId.toString();
    } catch (error) {
      throw new HostContractError(
        "CELL_ID_MISMATCH",
        "logical aggregate is not hosted by its routed physical cell",
        { cause: error },
      );
    }
    if (
      physicalCellId.length === 0 ||
      textEncoder.encode(physicalCellId).byteLength > MAX_PHYSICAL_ID_BYTES
    ) {
      throw new HostContractError("CELL_ID_MISMATCH", "physical cell ID is invalid");
    }
    return physicalCellId;
  }
}
