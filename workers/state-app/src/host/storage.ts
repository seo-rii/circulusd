import {
  decodeCanonicalCbor,
  digestBytes,
  encodeCanonicalCbor,
  isDigest,
  type Digest,
} from "@circulusd/protocol-types";

import {
  HostContractError,
  type CellRoutePort,
  type TransactionPort,
} from "./contracts.ts";

const MANIFEST_KEY = "circulusd.state-app.aggregate.v2.manifest";
const ANCHOR_KEY = "circulusd.state-app.aggregate.v2.anchor";
const CHUNK_KEY_PREFIX = "circulusd.state-app.aggregate.v2.chunk";
const RECORD_FORMAT_VERSION = 2 as const;
const CHUNK_BYTES = 1_048_576;
// A stored record is simultaneously encoded, decoded, normalized, validated,
// and cloned on command paths. Keep each copy below 4 MiB so the worst-case
// amplification remains bounded inside workerd's 128 MiB isolate limit.
const MAX_RECORD_BYTES = 4 * 1_048_576;
const MAX_RECORD_ITEMS = 100_000;
const MAX_RECORD_DEPTH = 72;
const MAX_CHUNKS = Math.ceil(MAX_RECORD_BYTES / CHUNK_BYTES);
const MAX_TRANSACTION_MUTATED_KEYS = 128;
const MAX_CELL_NAME_BYTES = 2_048;
const MAX_PHYSICAL_ID_BYTES = 256;
const textEncoder = new TextEncoder();

export interface StateRecord<State> {
  readonly formatVersion: typeof RECORD_FORMAT_VERSION;
  readonly aggregateKind: string;
  readonly initializationDigest: Digest;
  readonly cellName: string | null;
  readonly physicalCellId: string | null;
  readonly state: State;
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
  readonly #route: CellRoutePort | undefined;

  constructor(
    aggregateKind: string,
    validateState: (state: State) => void | Promise<void>,
    route?: CellRoutePort,
  ) {
    this.#aggregateKind = aggregateKind;
    this.#validateState = validateState;
    this.#route = route;
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
    const candidate = exactRecord(
      manifestSnapshot,
      [
        "aggregateKind",
        "cellName",
        "chunkCount",
        "encodedBytes",
        "formatVersion",
        "generationDigest",
        "initializationDigest",
        "physicalCellId",
      ],
      "stored manifest",
    );
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
    const manifest = candidate as unknown as StateManifest;
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
    const record = recordCandidate as unknown as StateRecord<State>;
    this.#assertStoredRoute(record);
    try {
      await this.#validateState(record.state);
    } catch (error) {
      throw new HostContractError("CORRUPT_STATE", "stored aggregate state is invalid", {
        cause: error,
      });
    }
    return { record, manifest };
  }

  async write(
    transaction: TransactionPort,
    record: StateRecord<State>,
    previousManifest?: StateManifest,
  ): Promise<void> {
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
    const chunkCount = Math.ceil(encoded.byteLength / CHUNK_BYTES);
    const oldChunkMutations =
      previousManifest === undefined || previousManifest.generationDigest === generationDigest
        ? 0
        : previousManifest.chunkCount;
    const initialAnchorMutation = previousManifest === undefined ? 1 : 0;
    if (
      chunkCount < 1 ||
      chunkCount > MAX_CHUNKS ||
      1 + initialAnchorMutation + chunkCount + oldChunkMutations >
        MAX_TRANSACTION_MUTATED_KEYS
    ) {
      throw new HostContractError(
        "INVALID_AGGREGATE_OUTPUT",
        "aggregate chunk count exceeds the atomic transaction limit",
      );
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
