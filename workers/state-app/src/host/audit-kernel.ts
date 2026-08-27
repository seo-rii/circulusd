import {
  digestStructuredValue,
  encodeCanonicalCbor,
  isDigest,
  type Digest,
} from "@circulusd/protocol-types";

import {
  AUDIT_GENESIS_HASH,
  CONTROL_STATE_SCHEMA_VERSION,
  applyPreparedAuditAppend,
  controlError,
  createAuditState,
  prepareAuditAppendCommand,
  validateAuditEntryReceipt,
  validateAuditReadRequest,
  validateAuditState,
  type AuditCommand,
  type AuditCommandOutcome,
  type AuditEntry,
  type ControlCommandReceipt,
  type CreateAuditStateInput,
} from "../control/index.ts";
import { AUDIT_STATE_MAX_BYTES } from "../control/validation.ts";
import { auditCellName } from "./names.ts";
import {
  HostContractError,
  type CellRoutePort,
  type CommittedCommandResult,
  type DurableObjectStatePort,
  type InitializationResult,
  type TransactionalStoragePort,
  type TransactionPort,
} from "./contracts.ts";

const AUDIT_STORAGE_FORMAT_VERSION = 1 as const;
const AUDIT_ANCHOR_KEY = "circulusd.state-app.audit.v1.anchor";
const AUDIT_HEAD_KEY = "circulusd.state-app.audit.v1.head";
const AUDIT_ENTRY_KEY_PREFIX = "circulusd.state-app.audit.v1.entry";
const AUDIT_COMMAND_KEY_PREFIX = "circulusd.state-app.audit.v1.command";
const AUDIT_COMMAND_COPY_KEY_PREFIX = "circulusd.state-app.audit.v1.command-copy";
const MAX_CELL_NAME_BYTES = 2_048;
const MAX_PHYSICAL_ID_BYTES = 256;
const MAX_AGGREGATE_RECORD_ITEMS = 100_000;
const AGGREGATE_RECORD_WRAPPER_ITEMS = 12;
const EMPTY_AUDIT_STATE_ITEMS = 13;
const textEncoder = new TextEncoder();

interface StoredAuditAnchor {
  readonly formatVersion: typeof AUDIT_STORAGE_FORMAT_VERSION;
  readonly aggregateKind: "audit";
  readonly initializationDigest: Digest;
  readonly cellName: string;
  readonly physicalCellId: string;
  readonly schemaVersion: typeof CONTROL_STATE_SCHEMA_VERSION;
  readonly tenantId: string;
}

interface StoredAuditHead {
  readonly formatVersion: typeof AUDIT_STORAGE_FORMAT_VERSION;
  readonly aggregateKind: "audit";
  readonly initializationDigest: Digest;
  readonly cellName: string;
  readonly physicalCellId: string;
  readonly schemaVersion: typeof CONTROL_STATE_SCHEMA_VERSION;
  readonly tenantId: string;
  readonly sequence: number;
  readonly headHash: Digest;
  readonly lastTimestamp: number | null;
  readonly entriesEncodedBytes: number;
  readonly receiptsEncodedBytes: number;
  readonly stateEncodedBytes: number;
  readonly entriesItems: number;
  readonly receiptsItems: number;
  readonly stateItems: number;
}

interface StoredAuditEntry {
  readonly formatVersion: typeof AUDIT_STORAGE_FORMAT_VERSION;
  readonly entry: AuditEntry;
  readonly receipt: ControlCommandReceipt<AuditCommandOutcome>;
  readonly entriesEncodedBytes: number;
  readonly receiptsEncodedBytes: number;
  readonly stateEncodedBytes: number;
  readonly entriesItems: number;
  readonly receiptsItems: number;
  readonly stateItems: number;
}

interface StoredAuditCommandIndex {
  readonly formatVersion: typeof AUDIT_STORAGE_FORMAT_VERSION;
  readonly commandId: string;
  readonly committedSequence: number;
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

function cloneStoredValue(value: unknown, label: string): unknown {
  try {
    return structuredClone(value);
  } catch (error) {
    throw new HostContractError("CORRUPT_STATE", `${label} cannot be cloned`, {
      cause: error,
    });
  }
}

function exactStoredRecord(
  value: unknown,
  expectedFields: readonly string[],
  label: string,
): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype &&
      Object.getPrototypeOf(value) !== null)
  ) {
    throw new HostContractError("CORRUPT_STATE", `${label} is not a plain object`);
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.some((key) => typeof key !== "string") ||
    keys.length !== expectedFields.length ||
    expectedFields.some((field) => !Object.prototype.hasOwnProperty.call(value, field))
  ) {
    throw new HostContractError("CORRUPT_STATE", `${label} shape is invalid`);
  }
  return value as Record<string, unknown>;
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

function checkedNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function encodedArrayHeaderBytes(length: number): number {
  if (length < 24) {
    return 1;
  }
  if (length <= 0xff) {
    return 2;
  }
  if (length <= 0xffff) {
    return 3;
  }
  if (length <= 0xffff_ffff) {
    return 5;
  }
  return 9;
}

function aggregateStateEncodedBytes(
  tenantId: string,
  sequence: number,
  headHash: Digest,
  entriesEncodedBytes: number,
  receiptsEncodedBytes: number,
): number {
  const emptyStateBytes = encodeCanonicalCbor({
    schemaVersion: CONTROL_STATE_SCHEMA_VERSION,
    tenantId,
    sequence,
    headHash,
    entries: [],
    commandReceipts: [],
  }).byteLength;
  return emptyStateBytes - 2 +
    encodedArrayHeaderBytes(sequence) * 2 +
    entriesEncodedBytes +
    receiptsEncodedBytes;
}

function normalizedItemCount(value: unknown): number {
  let items = 0;
  const pending = [value];
  while (pending.length > 0) {
    const current = pending.pop();
    items += 1;
    if (
      current === null ||
      typeof current !== "object" ||
      current instanceof Uint8Array
    ) {
      continue;
    }
    if (Array.isArray(current)) {
      pending.push(...current);
      continue;
    }
    const entries = Object.entries(current);
    items += entries.length;
    for (const [, entry] of entries) {
      pending.push(entry);
    }
  }
  return items;
}

function sequenceKey(sequence: number): string {
  return `${AUDIT_ENTRY_KEY_PREFIX}.${sequence.toString().padStart(16, "0")}`;
}

function encodedCommandKey(prefix: string, commandId: string): string {
  const encoded = textEncoder.encode(commandId);
  let suffix = "";
  for (const byte of encoded) {
    suffix += byte.toString(16).padStart(2, "0");
  }
  return `${prefix}.${suffix}`;
}

function commandKey(commandId: string): string {
  return encodedCommandKey(AUDIT_COMMAND_KEY_PREFIX, commandId);
}

function commandCopyKey(commandId: string): string {
  return encodedCommandKey(AUDIT_COMMAND_COPY_KEY_PREFIX, commandId);
}

function currentPhysicalCellId(route: CellRoutePort, cellName: string): string {
  if (
    cellName.length === 0 ||
    textEncoder.encode(cellName).byteLength > MAX_CELL_NAME_BYTES
  ) {
    throw new HostContractError("CELL_ID_MISMATCH", "logical cell name is invalid");
  }
  let physicalCellId: string;
  try {
    const expected = route.namespace.idFromName(cellName);
    if (!route.currentId.equals(expected)) {
      throw new Error("physical Durable Object ID differs from the routed ID");
    }
    physicalCellId = route.currentId.toString();
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

function corruptState(label: string, cause?: unknown): never {
  throw new HostContractError("CORRUPT_STATE", label, { cause });
}

export class AuditCellKernel {
  readonly #storage: TransactionalStoragePort;
  readonly #route: CellRoutePort;

  constructor(state: DurableObjectStatePort, route: CellRoutePort) {
    this.#storage = transactionalStorage(state);
    this.#route = route;
  }

  async initialize(initialization: CreateAuditStateInput): Promise<InitializationResult> {
    const initializationSnapshot = cloneBoundary(initialization, "initialization input");
    const candidate = createAuditState(initializationSnapshot);
    await validateAuditState(candidate);
    const initializationDigest = await digestStructuredValue(
      "circulusd.state-app.audit-initialization",
      1,
      initializationSnapshot,
    );
    const cellName = auditCellName(candidate.tenantId);
    const physicalCellId = currentPhysicalCellId(this.#route, cellName);
    const stateEncodedBytes = encodeCanonicalCbor(candidate).byteLength;
    const candidateAnchor: StoredAuditAnchor = {
      formatVersion: AUDIT_STORAGE_FORMAT_VERSION,
      aggregateKind: "audit",
      initializationDigest,
      cellName,
      physicalCellId,
      schemaVersion: CONTROL_STATE_SCHEMA_VERSION,
      tenantId: candidate.tenantId,
    };
    const candidateHead: StoredAuditHead = {
      formatVersion: AUDIT_STORAGE_FORMAT_VERSION,
      aggregateKind: "audit",
      initializationDigest,
      cellName,
      physicalCellId,
      schemaVersion: CONTROL_STATE_SCHEMA_VERSION,
      tenantId: candidate.tenantId,
      sequence: 0,
      headHash: AUDIT_GENESIS_HASH,
      lastTimestamp: null,
      entriesEncodedBytes: 0,
      receiptsEncodedBytes: 0,
      stateEncodedBytes,
      entriesItems: 0,
      receiptsItems: 0,
      stateItems: EMPTY_AUDIT_STATE_ITEMS,
    };

    const result = await this.#transact(async (transaction) => {
      const anchor = await this.#readAnchor(transaction);
      const existing = await this.#readHead(transaction);
      if (anchor === undefined && existing === undefined) {
        await transaction.put(AUDIT_ANCHOR_KEY, candidateAnchor);
        await transaction.put(AUDIT_HEAD_KEY, candidateHead);
        return { version: 0, replayed: false } satisfies InitializationResult;
      }
      if (anchor === undefined || existing === undefined) {
        corruptState("stored audit durable header is incomplete");
      }
      this.#assertAnchorMatchesHead(anchor, existing);
      await this.#assertHeadEdge(transaction, existing, new Map());
      if (existing.initializationDigest !== initializationDigest) {
        throw new HostContractError(
          "INITIALIZATION_CONFLICT",
          "audit cell was initialized with a different canonical digest",
        );
      }
      return {
        version: existing.sequence,
        replayed: true,
      } satisfies InitializationResult;
    });
    return cloneBoundary(result, "initialization result");
  }

  async execute(command: AuditCommand): Promise<CommittedCommandResult<AuditCommandOutcome>> {
    const commandSnapshot = cloneBoundary(command, "command input");
    const result = await this.#transact(async (transaction) => {
      const head = await this.#loadInitialized(transaction);
      const cache = new Map<number, StoredAuditEntry>();
      await this.#assertHeadEdge(transaction, head, cache);
      const prepared = await prepareAuditAppendCommand(head.tenantId, commandSnapshot);
      const index = await this.#readCommandIndex(
        transaction,
        prepared.commandId,
        head.sequence,
      );

      if (index !== undefined) {
        const stored = await this.#readEntry(transaction, index.committedSequence, cache);
        await this.#validateEntryWithPredecessor(
          transaction,
          head,
          index.committedSequence,
          stored,
          cache,
        );
        if (stored.receipt.commandId !== prepared.commandId) {
          corruptState("stored audit command index disagrees with its receipt");
        }
        const replayed = await applyPreparedAuditAppend(
          {
            tenantId: head.tenantId,
            sequence: head.sequence,
            headHash: head.headHash,
            previousTimestamp: head.lastTimestamp,
          },
          prepared,
          stored.receipt,
        );
        if (!replayed.replayed) {
          corruptState("stored audit replay unexpectedly produced an append");
        }
        return {
          outcome: cloneBoundary(replayed.outcome, "aggregate outcome"),
          version: head.sequence,
          replayed: true,
        } satisfies CommittedCommandResult<AuditCommandOutcome>;
      }

      const applied = await applyPreparedAuditAppend(
        {
          tenantId: head.tenantId,
          sequence: head.sequence,
          headHash: head.headHash,
          previousTimestamp: head.lastTimestamp,
        },
        prepared,
        undefined,
      );
      if (applied.replayed) {
        corruptState("new audit command unexpectedly replayed");
      }
      const entryEncodedBytes = encodeCanonicalCbor(applied.entry).byteLength;
      const receiptEncodedBytes = encodeCanonicalCbor(applied.receipt).byteLength;
      const entryItems = normalizedItemCount(applied.entry);
      const receiptItems = normalizedItemCount(applied.receipt);
      const entriesEncodedBytes = head.entriesEncodedBytes + entryEncodedBytes;
      const receiptsEncodedBytes = head.receiptsEncodedBytes + receiptEncodedBytes;
      const entriesItems = head.entriesItems + entryItems;
      const receiptsItems = head.receiptsItems + receiptItems;
      const stateItems = EMPTY_AUDIT_STATE_ITEMS + entriesItems + receiptsItems;
      const stateEncodedBytes = aggregateStateEncodedBytes(
        head.tenantId,
        applied.entry.sequence,
        applied.entry.hash,
        entriesEncodedBytes,
        receiptsEncodedBytes,
      );
      if (
        !Number.isSafeInteger(entriesEncodedBytes) ||
        !Number.isSafeInteger(receiptsEncodedBytes) ||
        !Number.isSafeInteger(stateEncodedBytes) ||
        stateEncodedBytes > AUDIT_STATE_MAX_BYTES
      ) {
        controlError(
          "RESOURCE_EXHAUSTED",
          `next state exceeds the ${AUDIT_STATE_MAX_BYTES}-byte audit limit`,
        );
      }
      if (
        !Number.isSafeInteger(entriesItems) ||
        !Number.isSafeInteger(receiptsItems) ||
        !Number.isSafeInteger(stateItems) ||
        stateItems + AGGREGATE_RECORD_WRAPPER_ITEMS > MAX_AGGREGATE_RECORD_ITEMS
      ) {
        throw new HostContractError(
          "INVALID_AGGREGATE_OUTPUT",
          `audit aggregate exceeds the ${MAX_AGGREGATE_RECORD_ITEMS}-item host limit`,
        );
      }
      const storedEntry: StoredAuditEntry = {
        formatVersion: AUDIT_STORAGE_FORMAT_VERSION,
        entry: cloneBoundary(applied.entry, "audit entry"),
        receipt: cloneBoundary(applied.receipt, "audit receipt"),
        entriesEncodedBytes,
        receiptsEncodedBytes,
        stateEncodedBytes,
        entriesItems,
        receiptsItems,
        stateItems,
      };
      const previous = head.sequence === 0
        ? null
        : await this.#readEntry(transaction, head.sequence, cache);
      await this.#validateStoredEntry(
        head.tenantId,
        applied.entry.sequence,
        storedEntry,
        previous,
      );
      const nextHead: StoredAuditHead = {
        ...head,
        sequence: applied.entry.sequence,
        headHash: applied.entry.hash,
        lastTimestamp: applied.entry.event.timestamp,
        entriesEncodedBytes,
        receiptsEncodedBytes,
        stateEncodedBytes,
        entriesItems,
        receiptsItems,
        stateItems,
      };
      const commandIndex: StoredAuditCommandIndex = {
        formatVersion: AUDIT_STORAGE_FORMAT_VERSION,
        commandId: prepared.commandId,
        committedSequence: applied.entry.sequence,
      };

      await transaction.put(sequenceKey(applied.entry.sequence), storedEntry);
      await transaction.put(commandKey(prepared.commandId), commandIndex);
      await transaction.put(commandCopyKey(prepared.commandId), commandIndex);
      await transaction.put(AUDIT_HEAD_KEY, nextHead);
      return {
        outcome: cloneBoundary(applied.outcome, "aggregate outcome"),
        version: applied.entry.sequence,
        replayed: false,
      } satisfies CommittedCommandResult<AuditCommandOutcome>;
    });
    return cloneBoundary(result, "committed command result");
  }

  async read(
    afterSequenceInput: number,
    limitInput: number,
    authority: Parameters<typeof validateAuditReadRequest>[3],
    now: number,
  ): Promise<AuditEntry[]> {
    const input = cloneBoundary(
      { afterSequenceInput, limitInput, authority, now },
      "read input",
    );
    const result = await this.#transact(async (transaction) => {
      const head = await this.#loadInitialized(transaction);
      const cache = new Map<number, StoredAuditEntry>();
      await this.#assertHeadEdge(transaction, head, cache);
      const { afterSequence, limit } = validateAuditReadRequest(
        head.tenantId,
        input.afterSequenceInput,
        input.limitInput,
        input.authority,
        input.now,
      );
      if (afterSequence >= head.sequence) {
        return [];
      }
      const firstSequence = afterSequence + 1;
      const lastSequence = Math.min(head.sequence, afterSequence + limit);
      let previous = firstSequence === 1
        ? null
        : await this.#readEntry(transaction, firstSequence - 1, cache);
      if (previous !== null) {
        await this.#validateStoredEntryContents(
          head.tenantId,
          firstSequence - 1,
          previous,
        );
      }
      const entries: AuditEntry[] = [];
      for (let sequence = firstSequence; sequence <= lastSequence; sequence += 1) {
        const stored = await this.#readEntry(transaction, sequence, cache);
        await this.#validateStoredEntry(head.tenantId, sequence, stored, previous);
        entries.push(cloneBoundary(stored.entry, "stored audit entry"));
        previous = stored;
      }
      return entries;
    });
    return cloneBoundary(result, "read result");
  }

  async #loadInitialized(transaction: TransactionPort): Promise<StoredAuditHead> {
    const anchor = await this.#readAnchor(transaction);
    const head = await this.#readHead(transaction);
    if (anchor === undefined && head === undefined) {
      throw new HostContractError("NOT_INITIALIZED", "audit cell is not initialized");
    }
    if (anchor === undefined || head === undefined) {
      corruptState("stored audit durable header is incomplete");
    }
    this.#assertAnchorMatchesHead(anchor, head);
    return head;
  }

  async #readAnchor(
    transaction: TransactionPort,
  ): Promise<StoredAuditAnchor | undefined> {
    const stored = await transaction.get<unknown>(AUDIT_ANCHOR_KEY);
    if (stored === undefined) {
      return undefined;
    }
    const candidate = exactStoredRecord(
      cloneStoredValue(stored, "stored audit anchor"),
      [
        "aggregateKind",
        "cellName",
        "formatVersion",
        "initializationDigest",
        "physicalCellId",
        "schemaVersion",
        "tenantId",
      ],
      "stored audit anchor",
    );
    if (
      candidate.formatVersion !== AUDIT_STORAGE_FORMAT_VERSION ||
      candidate.aggregateKind !== "audit" ||
      !isDigest(candidate.initializationDigest) ||
      candidate.schemaVersion !== CONTROL_STATE_SCHEMA_VERSION ||
      typeof candidate.tenantId !== "string" ||
      typeof candidate.cellName !== "string" ||
      typeof candidate.physicalCellId !== "string"
    ) {
      corruptState("stored audit anchor metadata is invalid");
    }
    return candidate as unknown as StoredAuditAnchor;
  }

  #assertAnchorMatchesHead(
    anchor: StoredAuditAnchor,
    head: StoredAuditHead,
  ): void {
    if (
      anchor.initializationDigest !== head.initializationDigest ||
      anchor.cellName !== head.cellName ||
      anchor.physicalCellId !== head.physicalCellId ||
      anchor.schemaVersion !== head.schemaVersion ||
      anchor.tenantId !== head.tenantId
    ) {
      corruptState("stored audit headers disagree");
    }
  }

  async #readHead(transaction: TransactionPort): Promise<StoredAuditHead | undefined> {
    const stored = await transaction.get<unknown>(AUDIT_HEAD_KEY);
    if (stored === undefined) {
      return undefined;
    }
    const candidate = exactStoredRecord(
      cloneStoredValue(stored, "stored audit head"),
      [
        "aggregateKind",
        "cellName",
        "entriesEncodedBytes",
        "entriesItems",
        "formatVersion",
        "headHash",
        "initializationDigest",
        "lastTimestamp",
        "physicalCellId",
        "receiptsEncodedBytes",
        "receiptsItems",
        "schemaVersion",
        "sequence",
        "stateEncodedBytes",
        "stateItems",
        "tenantId",
      ],
      "stored audit head",
    );
    if (
      candidate.formatVersion !== AUDIT_STORAGE_FORMAT_VERSION ||
      candidate.aggregateKind !== "audit" ||
      !isDigest(candidate.initializationDigest) ||
      candidate.schemaVersion !== CONTROL_STATE_SCHEMA_VERSION ||
      typeof candidate.tenantId !== "string" ||
      !checkedNonNegativeInteger(candidate.sequence) ||
      !isDigest(candidate.headHash) ||
      (candidate.lastTimestamp !== null &&
        !checkedNonNegativeInteger(candidate.lastTimestamp)) ||
      !checkedNonNegativeInteger(candidate.entriesEncodedBytes) ||
      !checkedNonNegativeInteger(candidate.receiptsEncodedBytes) ||
      !checkedNonNegativeInteger(candidate.stateEncodedBytes) ||
      !checkedNonNegativeInteger(candidate.entriesItems) ||
      !checkedNonNegativeInteger(candidate.receiptsItems) ||
      !checkedNonNegativeInteger(candidate.stateItems) ||
      typeof candidate.cellName !== "string" ||
      typeof candidate.physicalCellId !== "string"
    ) {
      corruptState("stored audit head metadata is invalid");
    }
    const head = candidate as unknown as StoredAuditHead;
    try {
      createAuditState({ tenantId: head.tenantId });
    } catch (error) {
      corruptState("stored audit tenant identity is invalid", error);
    }
    let expectedInitializationDigest: Digest;
    try {
      expectedInitializationDigest = await digestStructuredValue(
        "circulusd.state-app.audit-initialization",
        1,
        { tenantId: head.tenantId },
      );
    } catch (error) {
      corruptState("stored audit initialization cannot be verified", error);
    }
    if (head.initializationDigest !== expectedInitializationDigest) {
      corruptState("stored audit initialization digest is invalid");
    }
    const expectedCellName = auditCellName(head.tenantId);
    if (
      head.cellName !== expectedCellName ||
      textEncoder.encode(head.cellName).byteLength > MAX_CELL_NAME_BYTES ||
      head.physicalCellId.length === 0 ||
      textEncoder.encode(head.physicalCellId).byteLength > MAX_PHYSICAL_ID_BYTES
    ) {
      corruptState("stored audit cell route metadata is invalid");
    }
    const physicalCellId = currentPhysicalCellId(this.#route, expectedCellName);
    if (head.physicalCellId !== physicalCellId) {
      throw new HostContractError(
        "CELL_ID_MISMATCH",
        "stored audit aggregate is bound to a different physical cell",
      );
    }
    if (
      (head.sequence === 0 &&
        (head.headHash !== AUDIT_GENESIS_HASH ||
          head.lastTimestamp !== null ||
          head.entriesEncodedBytes !== 0 ||
          head.receiptsEncodedBytes !== 0 ||
          head.entriesItems !== 0 ||
          head.receiptsItems !== 0)) ||
      (head.sequence > 0 && head.lastTimestamp === null)
    ) {
      corruptState("stored audit head sequence metadata is inconsistent");
    }
    let expectedStateEncodedBytes: number;
    try {
      expectedStateEncodedBytes = aggregateStateEncodedBytes(
        head.tenantId,
        head.sequence,
        head.headHash,
        head.entriesEncodedBytes,
        head.receiptsEncodedBytes,
      );
    } catch (error) {
      corruptState("stored audit size metadata cannot be verified", error);
    }
    if (
      head.stateEncodedBytes !== expectedStateEncodedBytes ||
      head.stateEncodedBytes > AUDIT_STATE_MAX_BYTES ||
      head.stateItems !==
        EMPTY_AUDIT_STATE_ITEMS + head.entriesItems + head.receiptsItems ||
      head.stateItems + AGGREGATE_RECORD_WRAPPER_ITEMS > MAX_AGGREGATE_RECORD_ITEMS
    ) {
      corruptState("stored audit size metadata is invalid");
    }
    return head;
  }

  async #readEntry(
    transaction: TransactionPort,
    sequence: number,
    cache: Map<number, StoredAuditEntry>,
  ): Promise<StoredAuditEntry> {
    const cached = cache.get(sequence);
    if (cached !== undefined) {
      return cached;
    }
    const stored = await transaction.get<unknown>(sequenceKey(sequence));
    if (stored === undefined) {
      corruptState(`stored audit entry ${sequence} is missing`);
    }
    const candidate = exactStoredRecord(
      cloneStoredValue(stored, `stored audit entry ${sequence}`),
      [
        "entriesEncodedBytes",
        "entriesItems",
        "entry",
        "formatVersion",
        "receipt",
        "receiptsEncodedBytes",
        "receiptsItems",
        "stateEncodedBytes",
        "stateItems",
      ],
      `stored audit entry ${sequence}`,
    );
    if (
      candidate.formatVersion !== AUDIT_STORAGE_FORMAT_VERSION ||
      !checkedNonNegativeInteger(candidate.entriesEncodedBytes) ||
      !checkedNonNegativeInteger(candidate.receiptsEncodedBytes) ||
      !checkedNonNegativeInteger(candidate.stateEncodedBytes) ||
      !checkedNonNegativeInteger(candidate.entriesItems) ||
      !checkedNonNegativeInteger(candidate.receiptsItems) ||
      !checkedNonNegativeInteger(candidate.stateItems)
    ) {
      corruptState(`stored audit entry ${sequence} metadata is invalid`);
    }
    const result = candidate as unknown as StoredAuditEntry;
    cache.set(sequence, result);
    return result;
  }

  async #readCommandIndex(
    transaction: TransactionPort,
    commandId: string,
    maximumSequence: number,
  ): Promise<StoredAuditCommandIndex | undefined> {
    const stored = await transaction.get<unknown>(commandKey(commandId));
    const storedCopy = await transaction.get<unknown>(commandCopyKey(commandId));
    if (stored === undefined && storedCopy === undefined) {
      return undefined;
    }
    if (stored === undefined || storedCopy === undefined) {
      corruptState("stored audit command index copies are incomplete");
    }
    const indexes: StoredAuditCommandIndex[] = [];
    for (const [value, label] of [
      [stored, "stored audit command index"],
      [storedCopy, "stored audit command index copy"],
    ] as const) {
      const candidate = exactStoredRecord(
        cloneStoredValue(value, label),
        ["commandId", "committedSequence", "formatVersion"],
        label,
      );
      if (
        candidate.formatVersion !== AUDIT_STORAGE_FORMAT_VERSION ||
        candidate.commandId !== commandId ||
        !checkedNonNegativeInteger(candidate.committedSequence) ||
        candidate.committedSequence < 1 ||
        candidate.committedSequence > maximumSequence
      ) {
        corruptState(`${label} is invalid`);
      }
      indexes.push(candidate as unknown as StoredAuditCommandIndex);
    }
    const [index, indexCopy] = indexes;
    if (
      index === undefined ||
      indexCopy === undefined ||
      index.committedSequence !== indexCopy.committedSequence
    ) {
      corruptState("stored audit command index copies disagree");
    }
    return index;
  }

  async #validateStoredEntryContents(
    tenantId: string,
    expectedSequence: number,
    stored: StoredAuditEntry,
  ): Promise<void> {
    try {
      await validateAuditEntryReceipt(
        tenantId,
        expectedSequence,
        (stored.entry as AuditEntry).previousHash,
        null,
        stored.entry,
        stored.receipt,
      );
      const entry = stored.entry;
      const stateEncodedBytes = aggregateStateEncodedBytes(
        tenantId,
        expectedSequence,
        entry.hash,
        stored.entriesEncodedBytes,
        stored.receiptsEncodedBytes,
      );
      const entryItems = normalizedItemCount(entry);
      const receiptItems = normalizedItemCount(stored.receipt);
      if (
        stored.entriesEncodedBytes < encodeCanonicalCbor(entry).byteLength ||
        stored.receiptsEncodedBytes < encodeCanonicalCbor(stored.receipt).byteLength ||
        stored.stateEncodedBytes !== stateEncodedBytes ||
        stored.stateEncodedBytes > AUDIT_STATE_MAX_BYTES ||
        stored.entriesItems < entryItems ||
        stored.receiptsItems < receiptItems ||
        stored.stateItems !==
          EMPTY_AUDIT_STATE_ITEMS + stored.entriesItems + stored.receiptsItems ||
        stored.stateItems + AGGREGATE_RECORD_WRAPPER_ITEMS > MAX_AGGREGATE_RECORD_ITEMS
      ) {
        corruptState(`stored audit entry ${expectedSequence} size metadata is invalid`);
      }
    } catch (error) {
      if (error instanceof HostContractError) {
        throw error;
      }
      corruptState(`stored audit entry ${expectedSequence} is invalid`, error);
    }
  }

  async #validateStoredEntry(
    tenantId: string,
    expectedSequence: number,
    stored: StoredAuditEntry,
    previous: StoredAuditEntry | null,
  ): Promise<void> {
    try {
      if (previous !== null) {
        await this.#validateStoredEntryContents(
          tenantId,
          expectedSequence - 1,
          previous,
        );
      } else if (expectedSequence !== 1) {
        corruptState(`stored audit entry ${expectedSequence} has no predecessor`);
      }
      const expectedPreviousHash = previous === null
        ? AUDIT_GENESIS_HASH
        : previous.entry.hash;
      const previousTimestamp = previous?.entry.event.timestamp ?? null;
      await validateAuditEntryReceipt(
        tenantId,
        expectedSequence,
        expectedPreviousHash,
        previousTimestamp,
        stored.entry,
        stored.receipt,
      );
      const entryEncodedBytes = encodeCanonicalCbor(stored.entry).byteLength;
      const receiptEncodedBytes = encodeCanonicalCbor(stored.receipt).byteLength;
      const entryItems = normalizedItemCount(stored.entry);
      const receiptItems = normalizedItemCount(stored.receipt);
      const previousEntryBytes = previous?.entriesEncodedBytes ?? 0;
      const previousReceiptBytes = previous?.receiptsEncodedBytes ?? 0;
      const previousEntryItems = previous?.entriesItems ?? 0;
      const previousReceiptItems = previous?.receiptsItems ?? 0;
      if (
        stored.entriesEncodedBytes !== previousEntryBytes + entryEncodedBytes ||
        stored.receiptsEncodedBytes !== previousReceiptBytes + receiptEncodedBytes ||
        stored.entriesItems !== previousEntryItems + entryItems ||
        stored.receiptsItems !== previousReceiptItems + receiptItems ||
        stored.stateItems !==
          EMPTY_AUDIT_STATE_ITEMS + stored.entriesItems + stored.receiptsItems ||
        stored.stateEncodedBytes !== aggregateStateEncodedBytes(
          tenantId,
          expectedSequence,
          stored.entry.hash,
          stored.entriesEncodedBytes,
          stored.receiptsEncodedBytes,
        ) ||
        stored.stateEncodedBytes > AUDIT_STATE_MAX_BYTES ||
        stored.stateItems + AGGREGATE_RECORD_WRAPPER_ITEMS > MAX_AGGREGATE_RECORD_ITEMS
      ) {
        corruptState(`stored audit entry ${expectedSequence} size chain is invalid`);
      }
    } catch (error) {
      if (error instanceof HostContractError) {
        throw error;
      }
      corruptState(`stored audit entry ${expectedSequence} is invalid`, error);
    }
  }

  async #validateEntryWithPredecessor(
    transaction: TransactionPort,
    head: StoredAuditHead,
    expectedSequence: number,
    stored: StoredAuditEntry,
    cache: Map<number, StoredAuditEntry>,
  ): Promise<void> {
    const previous = expectedSequence === 1
      ? null
      : await this.#readEntry(transaction, expectedSequence - 1, cache);
    await this.#validateStoredEntry(
      head.tenantId,
      expectedSequence,
      stored,
      previous,
    );
  }

  async #assertHeadEdge(
    transaction: TransactionPort,
    head: StoredAuditHead,
    cache: Map<number, StoredAuditEntry>,
  ): Promise<void> {
    if (head.sequence === 0) {
      return;
    }
    const stored = await this.#readEntry(transaction, head.sequence, cache);
    await this.#validateEntryWithPredecessor(
      transaction,
      head,
      head.sequence,
      stored,
      cache,
    );
    if (
      stored.entry.hash !== head.headHash ||
      stored.entry.event.timestamp !== head.lastTimestamp ||
      stored.entriesEncodedBytes !== head.entriesEncodedBytes ||
      stored.receiptsEncodedBytes !== head.receiptsEncodedBytes ||
      stored.stateEncodedBytes !== head.stateEncodedBytes ||
      stored.entriesItems !== head.entriesItems ||
      stored.receiptsItems !== head.receiptsItems ||
      stored.stateItems !== head.stateItems
    ) {
      corruptState("stored audit head disagrees with the chain edge");
    }
  }

  async #transact<Result>(
    callback: (transaction: TransactionPort) => Promise<Result>,
  ): Promise<Result> {
    let callbackInvocations = 0;
    let callbackCompletions = 0;
    const result = await this.#storage.transaction(async (candidateTransaction) => {
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
