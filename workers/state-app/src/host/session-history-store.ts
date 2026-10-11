import { decodeCanonicalCbor, digestBytes, encodeCanonicalCbor, isDigest, type Digest, type NormalizedValue } from "@circulusd/protocol-types";
import { planSessionHistoryReads } from "../session/history.ts";
import { sessionPayloadItems } from "../session/payload.ts";
import { assertSessionBrokerReceipt } from "../session/broker.ts";
import type { SessionBrokerStoredReceipt } from "../session/broker-types.ts";
import type {
  ApplySessionCommandResult, CommandReceipt, SessionAggregateState, SessionApplyContext,
  SessionArchiveDelta, SessionCommand, SessionEffect, SessionHistoryWitness,
  SessionPublicEvent, SessionTurnIdentity, StoredSessionCommandOutcome, TurnAdmissionReceipt,
} from "../session/types.ts";
import { SESSION_HISTORY_MAX_RECORDS } from "../session/types.ts";
import { ArchivePlanningLimitError, HostContractError, type AggregateApplyContext, type TransactionPort } from "./contracts.ts";
import { emptySessionHistoryIndexRoot, SessionHistoryIndex, type SessionHistoryIndexRoot } from "./session-history-index.ts";
import type { AggregateTransactionCompanion } from "./kernel.ts";
import type { BlobRecordRef, StoredStateRecord } from "./storage.ts";

export const SESSION_HISTORY_EVENT_PAGE_SIZE = 16;
export const SESSION_HISTORY_ROW_PREFIX = "circulusd.state-app.session-history.v1.row.";
const CHUNK_BYTES = 1_048_576;
const MAX_ROW_BYTES = 4 * CHUNK_BYTES;
const MAX_ROW_ITEMS = 100_000;
interface Row { kind: string; value: unknown }
interface EventPage { pageNumber: number; events: SessionPublicEvent[] }

function corrupt(message: string): never {
  throw new HostContractError("CORRUPT_STATE", `Session history: ${message}`);
}
function exact(value: unknown, fields: readonly string[]): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).length === fields.length && fields.every((field) => Object.hasOwn(value, field));
}
export function sessionHistoryRowKey(digest: Digest, chunk: number | "header"): string {
  return `${SESSION_HISTORY_ROW_PREFIX}${digest}.${chunk}`;
}

async function readRow(transaction: Pick<TransactionPort, "get">, digest: Digest): Promise<Row> {
  const header = await transaction.get<unknown>(sessionHistoryRowKey(digest, "header"));
  if (!exact(header, ["encodedBytes"]) || typeof header.encodedBytes !== "number" ||
    !Number.isSafeInteger(header.encodedBytes) || header.encodedBytes < 1 || header.encodedBytes > MAX_ROW_BYTES) {
    corrupt("indexed row header is missing or invalid");
  }
  const bytes = new Uint8Array(header.encodedBytes);
  for (let offset = 0; offset < bytes.length; offset += CHUNK_BYTES) {
    const chunk = await transaction.get<unknown>(sessionHistoryRowKey(digest, offset / CHUNK_BYTES));
    if (!(chunk instanceof Uint8Array) || chunk.byteLength !== Math.min(CHUNK_BYTES, bytes.length - offset)) {
      corrupt("indexed row chunk is missing or invalid");
    }
    bytes.set(chunk, offset);
  }
  if (await digestBytes(bytes) !== digest) corrupt("indexed row digest mismatch");
  let value: unknown;
  try { value = decodeCanonicalCbor(bytes, { maxBytes: MAX_ROW_BYTES, maxDepth: 72, maxItems: MAX_ROW_ITEMS }); }
  catch { corrupt("indexed row is not bounded canonical CBOR"); }
  if (!exact(value, ["kind", "value"]) || typeof value.kind !== "string") corrupt("indexed row has an invalid envelope");
  return value as unknown as Row;
}

export function assertSessionHistoryAnchor(state: SessionAggregateState, root?: SessionHistoryIndexRoot): void {
  if (state.history !== undefined && (root === undefined || root.root === null || root.size === 0)) {
    corrupt("archived state lacks its nonempty index root");
  }
}

/** One transaction's bounded archive reads and writes; the root is persisted in its hot manifest. */
export class SessionHistoryStore {
  readonly #transaction: TransactionPort;
  readonly #index: SessionHistoryIndex;
  #encodedBytes = 0;
  #encodedItems = 0;
  constructor(transaction: TransactionPort, root?: SessionHistoryIndexRoot, state?: SessionAggregateState) {
    if (state !== undefined) assertSessionHistoryAnchor(state, root);
    this.#transaction = transaction;
    this.#index = new SessionHistoryIndex(transaction, root ?? emptySessionHistoryIndexRoot());
  }
  root(): SessionHistoryIndexRoot { return this.#index.root(); }
  async flush(): Promise<void> { await this.#index.flush(); }

  async #lookup<Value>(key: string, kind: string): Promise<Value | null> {
    const digest = await this.#index.get(key);
    if (digest === null) return null;
    const row = await readRow(this.#transaction, digest);
    if (row.kind !== kind) corrupt("index entry points to another record kind");
    return row.value as Value;
  }

  async #row(kind: string, value: unknown): Promise<Digest> {
    let bytes: Uint8Array;
    try { bytes = encodeCanonicalCbor({ kind, value }, { maxBytes: MAX_ROW_BYTES, maxDepth: 72, maxItems: MAX_ROW_ITEMS }); }
    catch (cause) { throw new HostContractError("INVALID_AGGREGATE_OUTPUT", "archive record exceeds its bounded encoding", { cause }); }
    this.#encodedBytes += bytes.byteLength;
    this.#encodedItems += sessionPayloadItems({ kind, value } as NormalizedValue);
    if (this.#encodedBytes > MAX_ROW_BYTES || this.#encodedItems > MAX_ROW_ITEMS) {
      throw new ArchivePlanningLimitError("Session archive batch exceeds its encoded byte/item budget");
    }
    const digest = await digestBytes(bytes);
    await this.#transaction.put(sessionHistoryRowKey(digest, "header"), { encodedBytes: bytes.byteLength });
    for (let offset = 0; offset < bytes.length; offset += CHUNK_BYTES) {
      await this.#transaction.put(sessionHistoryRowKey(digest, offset / CHUNK_BYTES), bytes.slice(offset, offset + CHUNK_BYTES));
    }
    return digest;
  }

  async #immutable(key: string, digest: Digest): Promise<void> {
    const prior = await this.#index.get(key);
    if (prior !== null && prior !== digest) corrupt("immutable identity index would be overwritten");
    await this.#index.set(key, digest);
  }

  async witnesses(state: SessionAggregateState, command: SessionCommand): Promise<SessionHistoryWitness> {
    const plan = planSessionHistoryReads(state, command);
    const result: SessionHistoryWitness = {};
    if (plan.brokerOperation !== undefined) {
      const query = plan.brokerOperation;
      const receipt = await this.brokerReceipt(query.kind, query.operationKey, query.operationKeyDigest);
      result.brokerOperation = { ...query, receipt };
      // Exact broker replay needs only its original immutable response. It does
      // not read freshly minted effect identities or reconstruct mutable effects.
      if (receipt !== null) return result;
    }
    if (plan.commandId !== undefined) {
      const receipt = await this.#lookup<CommandReceipt>(`command:${plan.commandId}`, "command");
      if (receipt !== null && receipt.commandId !== plan.commandId) corrupt("command receipt identity mismatch");
      result.command = { commandId: plan.commandId, receipt };
    }
    if (plan.idempotencyKeyDigest !== undefined) {
      const receipt = await this.#lookup<TurnAdmissionReceipt>(`admission:${plan.idempotencyKeyDigest}`, "admission");
      if (receipt !== null && receipt.idempotencyKeyDigest !== plan.idempotencyKeyDigest) corrupt("admission identity mismatch");
      result.admission = { idempotencyKeyDigest: plan.idempotencyKeyDigest, receipt };
    }
    if (plan.turnId !== undefined) {
      const record = await this.#lookup<SessionTurnIdentity>(`turn:${plan.turnId}`, "turn");
      if (record !== null && record.turnId !== plan.turnId) corrupt("turn identity mismatch");
      result.turn = { turnId: plan.turnId, record };
    }
    if (plan.effectId !== undefined) {
      const record = await this.#lookup<SessionEffect>(`effect:${plan.effectId}`, "effect");
      if (record !== null && record.effectId !== plan.effectId) corrupt("effect identity mismatch");
      result.effect = { effectId: plan.effectId, record };
    }
    if (plan.invocationId !== undefined) {
      const effect = await this.#lookup<SessionEffect>(`invocation:${plan.invocationId}`, "effect");
      if (effect !== null && effect.invocationId !== plan.invocationId) corrupt("invocation identity mismatch");
      result.invocation = { invocationId: plan.invocationId,
        record: effect === null ? null : { invocationId: effect.invocationId, effectId: effect.effectId } };
    }
    if (plan.issuingEventSequence !== undefined) {
      const receipt = await this.#lookup<CommandReceipt>(`receipt-sequence:${plan.issuingEventSequence}`, "command");
      if (receipt !== null && receipt.committedEventSequence !== plan.issuingEventSequence) corrupt("issuing receipt sequence mismatch");
      if (receipt === null && plan.issuingEventSequence >= 1 && plan.issuingEventSequence <= (state.history?.commandThrough ?? 0)) {
        corrupt("archived issuing receipt is missing");
      }
      result.issuingReceipt = { eventSequence: plan.issuingEventSequence, receipt };
    }
    // A start receipt may be archived while its effect has already left the hot
    // state. Load only that receipt's exact durable tombstone, never all effects.
    const replay = result.command?.receipt;
    const replayEffectId = replay?.outcome.kind === "dispatch_start_claimed" ? replay.outcome.effectId : undefined;
    if (replayEffectId !== undefined && !state.effects.some((effect) => effect.effectId === replayEffectId)) {
      const effectId = replayEffectId;
      const record = await this.#lookup<SessionEffect>(`effect:${effectId}`, "effect");
      if (record === null || record.effectId !== effectId) corrupt("archived start receipt lacks its effect tombstone");
      result.effect = { effectId, record };
    }
    return result;
  }

  async admissionReceipt(key: Digest): Promise<TurnAdmissionReceipt | null> {
    const receipt = await this.#lookup<TurnAdmissionReceipt>(`admission:${key}`, "admission");
    if (receipt !== null && receipt.idempotencyKeyDigest !== key) corrupt("admission identity mismatch");
    return receipt;
  }

  async brokerReceipt(kind: SessionBrokerStoredReceipt["kind"], operationKey: string,
    operationKeyDigest: Digest): Promise<SessionBrokerStoredReceipt | null> {
    const receipt = await this.#lookup<SessionBrokerStoredReceipt>(`broker-operation:${kind}:${operationKeyDigest}`, "broker-operation");
    if (receipt !== null) {
      assertSessionBrokerReceipt(receipt);
      if (receipt.kind !== kind || receipt.operationKey !== operationKey || receipt.operationKeyDigest !== operationKeyDigest) corrupt("broker receipt identity mismatch");
    }
    return receipt;
  }

  async blobReference(digest: Digest): Promise<BlobRecordRef | null> {
    const reference = await this.#lookup<BlobRecordRef>(`blob:${digest}`, "blob");
    if (reference !== null && (!exact(reference, ["digest", "encodedBytes"]) || reference.digest !== digest ||
      !Number.isSafeInteger(reference.encodedBytes) || reference.encodedBytes < 1 || reference.encodedBytes > MAX_ROW_BYTES)) {
      corrupt("archive blob pin is invalid");
    }
    return reference;
  }

  async #pin(reference: BlobRecordRef, available: ReadonlyMap<Digest, number>): Promise<void> {
    if (available.get(reference.digest) !== reference.encodedBytes) corrupt("archive row references an unavailable blob");
    const existing = await this.blobReference(reference.digest);
    if (existing !== null) {
      if (existing.encodedBytes !== reference.encodedBytes) corrupt("archive blob pin length mismatch");
      return;
    }
    await this.#immutable(`blob:${reference.digest}`, await this.#row("blob", reference));
  }

  async #appendEvents(events: readonly SessionPublicEvent[], previousThrough: number): Promise<void> {
    let through = previousThrough;
    for (let offset = 0; offset < events.length;) {
      const pageNumber = Math.floor(through / SESSION_HISTORY_EVENT_PAGE_SIZE);
      const key = `public-events:${pageNumber}`;
      const previousDigest = await this.#index.get(key);
      let page: EventPage = { pageNumber, events: [] };
      if (through % SESSION_HISTORY_EVENT_PAGE_SIZE !== 0) {
        if (previousDigest === null) corrupt("partial event page is missing");
        const previous = await readRow(this.#transaction, previousDigest);
        if (previous.kind !== "public-events") corrupt("event page kind mismatch");
        page = this.#eventPage(previous.value, pageNumber);
        if (page.events.length !== through % SESSION_HISTORY_EVENT_PAGE_SIZE) corrupt("event page does not match its watermark");
      } else if (previousDigest !== null) corrupt("new event page already exists");
      while (offset < events.length && page.events.length < SESSION_HISTORY_EVENT_PAGE_SIZE) {
        const event = events[offset++]!;
        if (event.sequence !== through + 1) corrupt("archive events are not a contiguous prefix");
        page.events.push(event);
        through += 1;
      }
      const digest = await this.#row("public-events", page);
      await this.#index.set(key, digest);
      // A page row includes its namespace/pageNumber and has exactly one index
      // owner. Replacing a partial page can reclaim only that previous row.
      if (previousDigest !== null && previousDigest !== digest) {
        const header = await this.#transaction.get<{ encodedBytes: number }>(sessionHistoryRowKey(previousDigest, "header"));
        if (header === undefined) corrupt("replaced event page header disappeared");
        for (let i = 0; i < Math.ceil(header.encodedBytes / CHUNK_BYTES); i += 1) {
          await this.#transaction.delete(sessionHistoryRowKey(previousDigest, i));
        }
        await this.#transaction.delete(sessionHistoryRowKey(previousDigest, "header"));
      }
    }
  }

  #eventPage(value: unknown, pageNumber: number): EventPage {
    if (!exact(value, ["pageNumber", "events"]) || value.pageNumber !== pageNumber ||
      !Array.isArray(value.events) || value.events.length < 1 || value.events.length > SESSION_HISTORY_EVENT_PAGE_SIZE ||
      value.events.some((event, index) => event === null || typeof event !== "object" ||
        event.sequence !== pageNumber * SESSION_HISTORY_EVENT_PAGE_SIZE + index + 1)) corrupt("event page is malformed");
    return value as unknown as EventPage;
  }

  async events(state: SessionAggregateState, afterSequence: number, limit: number): Promise<SessionPublicEvent[]> {
    if (!Number.isSafeInteger(afterSequence) || afterSequence < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 256) {
      return []; // The pure replay validator returns the public query error.
    }
    const end = Math.min(state.history?.publicEventThrough ?? 0, afterSequence + limit);
    const events: SessionPublicEvent[] = [];
    for (let sequence = afterSequence + 1; sequence <= end;) {
      const pageNumber = Math.floor((sequence - 1) / SESSION_HISTORY_EVENT_PAGE_SIZE);
      const value = await this.#lookup<EventPage>(`public-events:${pageNumber}`, "public-events");
      if (value === null) corrupt("archived public event page is missing");
      const page = this.#eventPage(value, pageNumber);
      for (; sequence <= end && sequence <= (pageNumber + 1) * SESSION_HISTORY_EVENT_PAGE_SIZE; sequence += 1) {
        const event = page.events[(sequence - 1) % SESSION_HISTORY_EVENT_PAGE_SIZE];
        if (event === undefined) corrupt("archived public event is missing");
        events.push(event);
      }
    }
    return events;
  }

  async archive(delta: SessionArchiveDelta, state: SessionAggregateState,
    references: readonly BlobRecordRef[], blobs?: ReadonlyMap<Digest, Uint8Array>): Promise<void> {
    const count = Object.values(delta).reduce((sum, rows) => sum + rows.length, 0);
    if (count > SESSION_HISTORY_MAX_RECORDS) throw new HostContractError("INVALID_AGGREGATE_OUTPUT", "archive batch exceeds its record limit");
    const available = new Map<Digest, number>(references.map((ref) => [ref.digest, ref.encodedBytes]));
    for (const [digest, bytes] of blobs ?? []) available.set(digest, bytes.byteLength);
    const pins = new Map<Digest, BlobRecordRef>();
    const add = (digest: Digest, encodedBytes: number) => pins.set(digest, { digest, encodedBytes });
    for (const receipt of delta.brokerReceipts ?? []) {
      assertSessionBrokerReceipt(receipt);
      const digest = await this.#row("broker-operation", receipt);
      await this.#immutable(`broker-operation:${receipt.kind}:${receipt.operationKeyDigest}`, digest);
      add(receipt.resultPayloadRef.digest, receipt.resultPayloadRef.encodedBytes);
      for (const reference of receipt.referencedBlobs) add(reference.digest, reference.encodedBytes);
    }
    for (const receipt of delta.commandReceipts) {
      const digest = await this.#row("command", receipt);
      await this.#immutable(`command:${receipt.commandId}`, digest);
      await this.#immutable(`receipt-sequence:${receipt.committedEventSequence}`, digest);
      const outcome = receipt.outcome;
      if (outcome.kind === "effect_settled" && outcome.settlement.kind === "success" && outcome.settlement.resultPayloadRef !== undefined) {
        add(outcome.settlement.resultPayloadRef.digest, outcome.settlement.resultPayloadRef.encodedBytes);
      }
    }
    for (const receipt of delta.turnAdmissionReceipts) {
      await this.#immutable(`admission:${receipt.idempotencyKeyDigest}`, await this.#row("admission", receipt));
    }
    for (const identity of delta.turnIdentities) await this.#immutable(`turn:${identity.turnId}`, await this.#row("turn", identity));
    for (const turn of delta.terminalTurns) {
      await this.#immutable(`terminal-turn:${turn.turnId}`, await this.#row("terminal-turn", turn));
      if (turn.inputRef !== undefined) add(turn.inputRef.digest, turn.inputRef.encodedBytes);
      if (!("payloadBytes" in turn.finalCheckpoint)) add(turn.finalCheckpoint.payloadDigest, turn.finalCheckpoint.payloadSize);
      if (turn.status === "completed" && turn.resultPayloadRef !== undefined) add(turn.resultPayloadRef.digest, turn.resultPayloadRef.encodedBytes);
      if (turn.status === "failed" && turn.error.detailsRef !== undefined) add(turn.error.detailsRef.digest, turn.error.detailsRef.encodedBytes);
    }
    for (const effect of delta.effects) {
      const digest = await this.#row("effect", effect);
      await this.#immutable(`effect:${effect.effectId}`, digest);
      await this.#immutable(`invocation:${effect.invocationId}`, digest);
      if (effect.requestPayloadRef !== undefined) add(effect.requestPayloadRef.digest, effect.requestPayloadRef.encodedBytes);
      if (effect.settlement?.kind === "success" && effect.settlement.resultPayloadRef !== undefined) add(effect.settlement.resultPayloadRef.digest, effect.settlement.resultPayloadRef.encodedBytes);
    }
    await this.#appendEvents(delta.publicEvents, state.history?.publicEventThrough ?? 0);
    for (const reference of pins.values()) await this.#pin(reference, available);
  }
}

export async function readArchivedSessionBlobReference(transaction: TransactionPort,
  root: SessionHistoryIndexRoot, digest: Digest): Promise<BlobRecordRef | null> {
  if (!isDigest(digest)) corrupt("invalid blob digest");
  return new SessionHistoryStore(transaction, root).blobReference(digest);
}

export const sessionHistoryCompanion: AggregateTransactionCompanion<SessionAggregateState,
  SessionCommand, StoredSessionCommandOutcome, SessionApplyContext, ApplySessionCommandResult> = {
  async prepareContext(transaction, stored, command, context: AggregateApplyContext) {
    const store = new SessionHistoryStore(transaction, stored.manifest.sessionHistory, stored.record.state);
    const history = await store.witnesses(stored.record.state, command);
    return { ...context, history, historyMaxRecords: SESSION_HISTORY_MAX_RECORDS };
  },
  async persist(transaction, stored: StoredStateRecord<SessionAggregateState>, _command, applied) {
    const store = new SessionHistoryStore(transaction, stored.manifest.sessionHistory, stored.record.state);
    if (applied.archiveDelta !== undefined) {
      await store.archive(applied.archiveDelta, stored.record.state, stored.manifest.referencedBlobs, applied.blobs);
    }
    await store.flush();
    return store.root();
  },
  reduceArchiveBatch(context) {
    const count = context.historyMaxRecords ?? SESSION_HISTORY_MAX_RECORDS;
    return count <= 1 ? undefined : { ...context, historyMaxRecords: Math.max(1, Math.floor(count / 2)) };
  },
};
