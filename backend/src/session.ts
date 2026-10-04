import { randomUUID } from "node:crypto";

/**
 * In-memory stand-in for circulusd's Session durable object: one append-only
 * durable event log with monotonically increasing ids (the SSE replay cursor),
 * one active turn at a time (single program counter), and an idempotency map
 * for turn submission. Nothing here survives a process restart.
 */
export interface DurableEvent {
  readonly id: number;
  readonly type: string;
  readonly sessionId: string;
  readonly turnId: string | null;
  readonly at: number;
  readonly data: unknown;
}

export interface EphemeralEvent {
  readonly id: null;
  readonly type: string;
  readonly sessionId: string;
  readonly turnId: string | null;
  readonly at: number;
  readonly data: unknown;
}

export type SessionEvent = DurableEvent | EphemeralEvent;
export type SessionEventListener = (event: SessionEvent) => void;

export type TurnStatus = "running" | "completed" | "failed" | "aborted";

export interface TurnError {
  readonly code: string;
  readonly message: string;
}

export interface TurnRecord {
  readonly turnId: string;
  readonly prompt: string;
  readonly createdAt: number;
  readonly controller: AbortController;
  status: TurnStatus;
  finishedAt: number | null;
  result: string | null;
  error: TurnError | null;
}

export interface TranscriptEntry {
  readonly role: "user" | "assistant";
  readonly text: string;
  readonly turnId: string;
}

/**
 * Per-session retention. The log and transcript would otherwise grow for as
 * long as a session lives; the oldest entries are dropped past these. A client
 * replaying from before the retained window gets what is retained (its
 * `stream.open` says where the window starts).
 */
export const MAX_EVENTS_PER_SESSION = 5_000;
export const MAX_TRANSCRIPT_ENTRIES = 400;
/** Finished turn records kept (each holds its prompt and result); the running turn is never dropped. */
export const MAX_TURNS_PER_SESSION = 200;

export class Session {
  readonly id: string;
  readonly createdAt = Date.now();
  readonly runtimeRevisionDigest: string;
  /** The retained tail of the durable log (see MAX_EVENTS_PER_SESSION). */
  readonly events: DurableEvent[] = [];
  /** The newest turns (see MAX_TURNS_PER_SESSION), oldest first. */
  readonly turns: TurnRecord[] = [];
  readonly transcript: TranscriptEntry[] = [];
  activeTurn: TurnRecord | null = null;
  readonly #listeners = new Set<SessionEventListener>();
  readonly #idempotency = new Map<string, string>();
  #nextEventId = 1;
  #lastActivityAt = this.createdAt;

  constructor(runtimeRevisionDigest: string, id: string = newIdentifier("sess")) {
    this.id = id;
    this.runtimeRevisionDigest = runtimeRevisionDigest;
  }

  get lastEventId(): number {
    return this.#nextEventId - 1;
  }

  /** When the session last did anything durable (its last event, or its creation). */
  get lastActivityAt(): number {
    return this.#lastActivityAt;
  }

  /** Id of the oldest event still retained (lastEventId + 1 when the log is empty). */
  get firstEventId(): number {
    return this.events[0]?.id ?? this.#nextEventId;
  }

  /** Append a durable event; it is replayable through `Last-Event-ID` while retained. */
  commit(type: string, turnId: string | null, data: unknown): DurableEvent {
    const event: DurableEvent = {
      id: this.#nextEventId,
      type,
      sessionId: this.id,
      turnId,
      at: Date.now(),
      data,
    };
    this.#nextEventId += 1;
    this.#lastActivityAt = event.at;
    this.events.push(event);
    if (this.events.length > MAX_EVENTS_PER_SESSION) this.events.splice(0, this.events.length - MAX_EVENTS_PER_SESSION);
    this.#fanout(event);
    return event;
  }

  /** Records a finished exchange for history injection, keeping the newest MAX_TRANSCRIPT_ENTRIES. */
  remember(...entries: TranscriptEntry[]): void {
    this.transcript.push(...entries);
    if (this.transcript.length > MAX_TRANSCRIPT_ENTRIES) {
      this.transcript.splice(0, this.transcript.length - MAX_TRANSCRIPT_ENTRIES);
      // Keep user/assistant pairs intact for the model.
      while (this.transcript.length > 0 && this.transcript[0]?.role !== "user") this.transcript.shift();
    }
  }

  /** Publish an ephemeral event (e.g. a model delta); never replayed. */
  emit(type: string, turnId: string | null, data: unknown): EphemeralEvent {
    const event: EphemeralEvent = {
      id: null,
      type,
      sessionId: this.id,
      turnId,
      at: Date.now(),
      data,
    };
    this.#fanout(event);
    return event;
  }

  /**
   * Replay retained durable events after `afterEventId`, then follow live
   * events. Events older than the retained window cannot be replayed.
   */
  subscribe(listener: SessionEventListener, afterEventId = 0): () => void {
    for (const event of this.events) {
      if (event.id > afterEventId) listener(event);
    }
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  }

  beginTurn(prompt: string): TurnRecord {
    if (this.activeTurn !== null) {
      throw new Error(`turn ${this.activeTurn.turnId} is still active`);
    }
    const turn: TurnRecord = {
      turnId: newIdentifier("turn"),
      prompt,
      createdAt: Date.now(),
      controller: new AbortController(),
      status: "running",
      finishedAt: null,
      result: null,
      error: null,
    };
    this.turns.push(turn);
    this.activeTurn = turn;
    if (this.turns.length > MAX_TURNS_PER_SESSION) {
      const dropped = new Set(this.turns.splice(0, this.turns.length - MAX_TURNS_PER_SESSION).map((old) => old.turnId));
      // A replayed Idempotency-Key must not point at a turn that no longer exists.
      for (const [key, turnId] of this.#idempotency) {
        if (dropped.has(turnId)) this.#idempotency.delete(key);
      }
    }
    return turn;
  }

  findTurn(turnId: string): TurnRecord | undefined {
    return this.turns.find((turn) => turn.turnId === turnId);
  }

  idempotentTurnId(key: string): string | undefined {
    return this.#idempotency.get(key);
  }

  rememberIdempotency(key: string, turnId: string): void {
    this.#idempotency.set(key, turnId);
  }

  snapshot(): Record<string, unknown> {
    return {
      sessionId: this.id,
      createdAt: this.createdAt,
      runtimeRevisionDigest: this.runtimeRevisionDigest,
      lastEventId: this.lastEventId,
      activeTurnId: this.activeTurn?.turnId ?? null,
      turns: this.turns.map((turn) => ({
        turnId: turn.turnId,
        prompt: turn.prompt,
        status: turn.status,
        createdAt: turn.createdAt,
        finishedAt: turn.finishedAt,
        result: turn.result,
        error: turn.error,
      })),
      transcript: this.transcript,
    };
  }

  #fanout(event: SessionEvent): void {
    for (const listener of this.#listeners) {
      try {
        listener(event);
      } catch {
        // A broken subscriber must never poison the turn runner.
      }
    }
  }
}

export interface SessionStoreOptions {
  /** Sessions kept in memory at once; the longest-idle one without a running turn is evicted beyond this. */
  readonly limit?: number;
  /** Called with each evicted session so per-session resources (the python sandbox, SSE streams) can go. */
  readonly onEvict?: (session: Session) => void;
}

export const DEFAULT_SESSION_LIMIT = 200;

export class SessionStore {
  readonly #sessions = new Map<string, Session>();
  readonly #limit: number;
  readonly #onEvict: ((session: Session) => void) | undefined;

  constructor(options: SessionStoreOptions = {}) {
    this.#limit = options.limit ?? DEFAULT_SESSION_LIMIT;
    this.#onEvict = options.onEvict;
  }

  /** Creates a session; returns null when the store is full of sessions with running turns. */
  create(runtimeRevisionDigest: string): Session | null {
    while (this.#sessions.size >= this.#limit) {
      const victim = this.#idleVictim();
      if (victim === undefined) return null;
      this.#sessions.delete(victim.id);
      this.#onEvict?.(victim);
    }
    const session = new Session(runtimeRevisionDigest);
    this.#sessions.set(session.id, session);
    return session;
  }

  #idleVictim(): Session | undefined {
    let victim: Session | undefined;
    for (const session of this.#sessions.values()) {
      if (session.activeTurn !== null) continue;
      if (victim === undefined || session.lastActivityAt < victim.lastActivityAt) victim = session;
    }
    return victim;
  }

  get(sessionId: string): Session | undefined {
    return this.#sessions.get(sessionId);
  }

  delete(sessionId: string): boolean {
    const session = this.#sessions.get(sessionId);
    if (session === undefined) return false;
    session.activeTurn?.controller.abort();
    return this.#sessions.delete(sessionId);
  }

  list(): Session[] {
    return [...this.#sessions.values()];
  }
}

function newIdentifier(prefix: string): string {
  return `${prefix}_${randomUUID().replace(/-/g, "")}`;
}
