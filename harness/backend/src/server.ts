import { readFile, stat } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { extname, resolve, sep } from "node:path";

import {
  PI_AGENT_CORE_ADAPTER_ABI_VERSION,
  PI_AGENT_CORE_PACKAGE_VERSION,
  getPiWorkerdConformanceStatus,
} from "@circulusd/pi-runtime";

import {
  CHECKPOINT_SCHEMA_VERSION,
  buildAdapterConfiguration,
  engineIdentity,
  runtimeRevisionDigest,
} from "./agent-config.ts";
import type { ModelProvider } from "./providers/index.ts";
import { SessionStore, type Session, type SessionEvent } from "./session.ts";
import type { ToolDefinition } from "./tools.ts";
import { createTurnRuntime, runTurn, type TurnRuntime } from "./turn-runner.ts";

export interface AppOptions {
  readonly provider: ModelProvider;
  readonly tools: readonly ToolDefinition[];
  /** How the python tool executes (see PythonExecutor.describe); reported in /v1/capabilities. A function is called per request. */
  readonly execution?: Record<string, unknown> | (() => Record<string, unknown>);
  readonly frontendDirectory: string | null;
  readonly historyInjection: boolean;
  readonly log?: (line: string) => void;
  /** Sessions kept in memory; beyond this the longest-idle session without a running turn is evicted. */
  readonly maxSessions?: number;
  /** Called after a session is deleted or evicted so executors can drop per-session state (the python sandbox). */
  readonly onSessionDeleted?: (sessionId: string) => Promise<void>;
}

export interface App {
  readonly server: Server;
  readonly store: SessionStore;
  readonly runtime: TurnRuntime;
  readonly runtimeRevisionDigest: string;
  listen(host: string, port: number): Promise<{ readonly host: string; readonly port: number }>;
  close(): Promise<void>;
}

const MAX_BODY_BYTES = 1_048_576;
/** A prompt is stored in the log and the transcript and sent to the model every later turn. */
const MAX_PROMPT_CHARS = 64 * 1024;
const MAX_IDEMPOTENCY_KEY_CHARS = 256;
const SSE_HEARTBEAT_MS = 15_000;
/**
 * Bytes an SSE client may leave unread before it is dropped. A client that
 * stopped reading (a stalled tab, a half-open connection) would otherwise make
 * the backend buffer every model delta for it indefinitely. The client
 * reconnects with Last-Event-ID and gets the durable events it missed.
 */
const SSE_MAX_BUFFERED_BYTES = 4 * 1024 * 1024;
const STATIC_CONTENT_TYPES: Readonly<Record<string, string>> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
};

class HttpError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: Record<string, unknown>;
  constructor(status: number, code: string, message: string, details: Record<string, unknown> = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export function createApp(options: AppOptions): App {
  const log = options.log ?? ((line: string) => console.log(line));
  const configuration = buildAdapterConfiguration(options.provider.configuration, options.tools);
  const digest = runtimeRevisionDigest(configuration);
  const runtime = createTurnRuntime({
    provider: options.provider,
    tools: options.tools,
    configuration,
    identity: (sessionId) => engineIdentity(sessionId, digest),
    historyInjection: options.historyInjection,
  });
  const frontendRoot = options.frontendDirectory === null ? null : resolve(options.frontendDirectory);
  // Open SSE streams per session (each entry closes one), so a deleted or
  // evicted session's streams are ended (the browser then learns the session
  // is gone instead of waiting on a stream nothing will ever write to again).
  const sseClients = new Map<string, Set<() => void>>();
  const dropSessionResources = (session: Session, reason: string): void => {
    // Streams first: the abort below makes the turn runner commit its final
    // events, which must not land on a response that has already been ended.
    const closers = sseClients.get(session.id);
    sseClients.delete(session.id); // before closing: close() would otherwise edit the set being iterated
    if (closers !== undefined) for (const close of closers) close();
    session.activeTurn?.controller.abort();
    log(`session ${session.id} ${reason}`);
    options.onSessionDeleted?.(session.id).catch((error: unknown) => {
      log(`session ${session.id} cleanup failed: ${error instanceof Error ? error.message : String(error)}`);
    });
  };
  const store = new SessionStore({
    ...(options.maxSessions === undefined ? {} : { limit: options.maxSessions }),
    onEvict: (session) => dropSessionResources(session, "evicted (session limit reached)"),
  });

  const capabilities = (): Record<string, unknown> => ({
    service: "circulusd-test",
    version: "0.1.0",
    engine: {
      package: "@circulusd/pi-runtime",
      piAgentCore: PI_AGENT_CORE_PACKAGE_VERSION,
      adapterAbiVersion: PI_AGENT_CORE_ADAPTER_ABI_VERSION,
      checkpointSchemaVersion: CHECKPOINT_SCHEMA_VERSION,
    },
    runtimeRevisionDigest: digest,
    model: options.provider.describe(),
    tools: options.tools.map((tool) => ({
      name: tool.name,
      description: tool.description,
      replayPolicy: tool.replayPolicy,
    })),
    historyInjection: options.historyInjection,
    execution: {
      baseTools: "echo, now, calculator run in-process inside the backend",
      python: (typeof options.execution === "function" ? options.execution() : options.execution) ?? { mode: "disabled" },
    },
    upstream: { piWorkerdConformance: getPiWorkerdConformanceStatus() },
    systemPrompt: configuration.systemPrompt,
  });

  const handle = async (request: IncomingMessage, response: ServerResponse): Promise<void> => {
    const url = new URL(request.url ?? "/", "http://localhost");
    const method = request.method ?? "GET";
    const path = url.pathname;

    if (path === "/v1/capabilities" || path === "/v1/status") {
      if (method !== "GET") throw new HttpError(405, "METHOD_NOT_ALLOWED", `${method} is not allowed`);
      sendJson(response, 200, capabilities());
      return;
    }

    if (path === "/v1/sessions") {
      if (method === "POST") {
        await readJson(request);
        const session = store.create(digest);
        if (session === null) {
          throw new HttpError(503, "SESSION_LIMIT", "every session slot has a running turn; try again later");
        }
        log(`session ${session.id} created`);
        sendJson(response, 201, {
          sessionId: session.id,
          runtimeRevision: "rev_local",
          runtimeRevisionDigest: digest,
          executionEnvironmentRevision: "in-process",
          resolvedPolicy: {
            agentIsolation: { processScope: "shared", outerIsolation: "none" },
            executionBackend: "in-process",
            sandboxScope: "none",
            networkMode: options.provider.describe().kind === "mock" ? "none" : "model-gateway-only",
          },
          eventsUrl: `/v1/sessions/${session.id}/events`,
        });
        return;
      }
      if (method === "GET") {
        // Summaries only: a full snapshot per session (turns, transcript) would grow with every chat.
        sendJson(response, 200, {
          sessions: store.list().map((session) => ({
            sessionId: session.id,
            createdAt: session.createdAt,
            lastActivityAt: session.lastActivityAt,
            lastEventId: session.lastEventId,
            activeTurnId: session.activeTurn?.turnId ?? null,
            turns: session.turns.length,
          })),
        });
        return;
      }
      throw new HttpError(405, "METHOD_NOT_ALLOWED", `${method} is not allowed`);
    }

    const sessionMatch = /^\/v1\/sessions\/([A-Za-z0-9_-]+)(\/.*)?$/.exec(path);
    if (sessionMatch !== null) {
      const sessionId = sessionMatch[1] ?? "";
      const rest = sessionMatch[2] ?? "";
      const session = store.get(sessionId);
      if (session === undefined) {
        throw new HttpError(404, "SESSION_NOT_FOUND", `session ${sessionId} does not exist`);
      }

      if (rest === "") {
        if (method === "GET") {
          sendJson(response, 200, session.snapshot());
          return;
        }
        if (method === "DELETE") {
          store.delete(sessionId);
          dropSessionResources(session, "deleted");
          response.writeHead(204).end();
          return;
        }
        throw new HttpError(405, "METHOD_NOT_ALLOWED", `${method} is not allowed`);
      }

      if (rest === "/turns") {
        if (method !== "POST") throw new HttpError(405, "METHOD_NOT_ALLOWED", `${method} is not allowed`);
        await submitTurn(request, response, session);
        return;
      }

      if (rest === "/events") {
        if (method !== "GET") throw new HttpError(405, "METHOD_NOT_ALLOWED", `${method} is not allowed`);
        streamEvents(request, response, session, url);
        return;
      }

      const abortMatch = /^\/turns\/([A-Za-z0-9_-]+)\/abort$/.exec(rest);
      if (abortMatch !== null) {
        if (method !== "POST") throw new HttpError(405, "METHOD_NOT_ALLOWED", `${method} is not allowed`);
        const turn = session.findTurn(abortMatch[1] ?? "");
        if (turn === undefined) {
          throw new HttpError(404, "TURN_NOT_FOUND", `turn ${abortMatch[1]} does not exist`);
        }
        if (turn.status !== "running") {
          throw new HttpError(409, "TURN_FINISHED", `turn ${turn.turnId} already ${turn.status}`);
        }
        turn.controller.abort();
        log(`turn ${turn.turnId} abort requested`);
        sendJson(response, 202, { sessionId, turnId: turn.turnId, status: "aborting" });
        return;
      }

      throw new HttpError(404, "NOT_FOUND", `no route for ${method} ${path}`);
    }

    if (path.startsWith("/v1/")) {
      throw new HttpError(404, "NOT_FOUND", `no route for ${method} ${path}`);
    }

    if (frontendRoot !== null && (method === "GET" || method === "HEAD")) {
      await serveStatic(response, frontendRoot, path, method === "HEAD");
      return;
    }
    throw new HttpError(404, "NOT_FOUND", `no route for ${method} ${path}`);
  };

  const submitTurn = async (
    request: IncomingMessage,
    response: ServerResponse,
    session: Session,
  ): Promise<void> => {
    const body = await readJson(request);
    const prompt = extractPrompt(body);
    if (prompt === null) {
      throw new HttpError(
        400,
        "INVALID_TURN",
        'body must be {"messages":[{"role":"user","content":"..."}]} or {"prompt":"..."}',
      );
    }
    if (prompt.length > MAX_PROMPT_CHARS) {
      throw new HttpError(400, "PROMPT_TOO_LONG", `prompt exceeds ${MAX_PROMPT_CHARS} characters`);
    }
    const keyHeader = request.headers["idempotency-key"];
    const idempotencyKey = Array.isArray(keyHeader) ? keyHeader[0] : keyHeader;
    if (idempotencyKey !== undefined && idempotencyKey.length > MAX_IDEMPOTENCY_KEY_CHARS) {
      throw new HttpError(400, "INVALID_IDEMPOTENCY_KEY", `Idempotency-Key exceeds ${MAX_IDEMPOTENCY_KEY_CHARS} characters`);
    }
    if (idempotencyKey !== undefined && idempotencyKey !== "") {
      const existing = session.idempotentTurnId(idempotencyKey);
      if (existing !== undefined) {
        sendJson(response, 202, {
          sessionId: session.id,
          turnId: existing,
          status: "accepted",
          replayed: true,
          eventsUrl: `/v1/sessions/${session.id}/events`,
        });
        return;
      }
    }
    if (session.activeTurn !== null) {
      throw new HttpError(409, "TURN_ACTIVE", `turn ${session.activeTurn.turnId} is still running`, {
        activeTurnId: session.activeTurn.turnId,
      });
    }
    const turn = session.beginTurn(prompt);
    if (idempotencyKey !== undefined && idempotencyKey !== "") {
      session.rememberIdempotency(idempotencyKey, turn.turnId);
    }
    log(`turn ${turn.turnId} accepted on ${session.id}: ${JSON.stringify(prompt.slice(0, 80))}`);
    void runTurn(session, turn, runtime)
      .catch((error: unknown) => {
        log(`turn ${turn.turnId} runner crashed: ${error instanceof Error ? error.stack ?? error.message : String(error)}`);
      })
      .finally(() => {
        log(`turn ${turn.turnId} ${turn.status}${turn.error === null ? "" : ` (${turn.error.code})`}`);
      });
    sendJson(response, 202, {
      sessionId: session.id,
      turnId: turn.turnId,
      status: "accepted",
      replayed: false,
      eventsUrl: `/v1/sessions/${session.id}/events`,
    });
  };

  const streamEvents = (
    request: IncomingMessage,
    response: ServerResponse,
    session: Session,
    url: URL,
  ): void => {
    const header = request.headers["last-event-id"];
    const raw = (Array.isArray(header) ? header[0] : header) ?? url.searchParams.get("lastEventId") ?? "0";
    const lastEventId = /^\d{1,15}$/.test(raw) ? Number(raw) : 0;
    response.writeHead(200, {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      "x-accel-buffering": "no",
    });
    response.write("retry: 1000\n\n");
    // Writing to a response after it ended (or to one the socket has already
    // torn down) raises ERR_STREAM_WRITE_AFTER_END as an 'error' event, which
    // without a listener takes the whole process down.
    response.on("error", (error) => log(`sse ${session.id}: ${error.message}`));
    let closed = false;
    let unsubscribe = (): void => undefined;
    const writable = (): boolean => !closed && !response.writableEnded && !response.destroyed;
    // Detaches from the session and ends the response. Idempotent, and safe
    // to call before the socket has actually closed.
    const close = (): void => {
      if (closed) return;
      closed = true;
      clearInterval(heartbeat);
      unsubscribe();
      const remaining = sseClients.get(session.id);
      if (remaining !== undefined) {
        remaining.delete(close);
        if (remaining.size === 0) sseClients.delete(session.id);
      }
      if (!response.writableEnded && !response.destroyed) response.end();
    };
    const write = (event: SessionEvent): void => {
      if (!writable()) return;
      if (response.writableLength > SSE_MAX_BUFFERED_BYTES) {
        log(`sse ${session.id}: client is not reading (${response.writableLength} bytes pending); dropping it`);
        close();
        response.destroy();
        return;
      }
      const lines = [
        ...(event.id === null ? [] : [`id: ${event.id}`]),
        `event: ${event.type}`,
        `data: ${JSON.stringify(event)}`,
      ];
      response.write(`${lines.join("\n")}\n\n`);
    };
    const heartbeat = setInterval(() => {
      if (writable()) response.write(": ping\n\n");
    }, SSE_HEARTBEAT_MS);
    let clients = sseClients.get(session.id);
    if (clients === undefined) {
      clients = new Set();
      sseClients.set(session.id, clients);
    }
    clients.add(close);
    request.on("close", close);
    response.on("close", close);
    write({
      id: null,
      type: "stream.open",
      sessionId: session.id,
      turnId: session.activeTurn?.turnId ?? null,
      at: Date.now(),
      // firstEventId > resumeFrom + 1 means older events were dropped and cannot be replayed.
      data: { resumeFrom: lastEventId, firstEventId: session.firstEventId, lastEventId: session.lastEventId },
    });
    // Replays the retained log first; a client that cannot take it all is closed by write().
    unsubscribe = session.subscribe(write, lastEventId);
    if (closed) unsubscribe();
  };

  const server = createServer((request, response) => {
    handle(request, response).catch((error: unknown) => {
      if (response.headersSent) {
        response.end();
        return;
      }
      if (error instanceof HttpError) {
        sendJson(response, error.status, {
          error: { code: error.code, message: error.message, ...error.details },
        });
        return;
      }
      log(`unhandled error: ${error instanceof Error ? error.stack ?? error.message : String(error)}`);
      sendJson(response, 500, {
        error: { code: "INTERNAL", message: error instanceof Error ? error.message : String(error) },
      });
    });
  });
  server.keepAliveTimeout = 65_000;

  return {
    server,
    store,
    runtime,
    runtimeRevisionDigest: digest,
    listen(host, port) {
      return new Promise((resolveListen, rejectListen) => {
        server.once("error", rejectListen);
        server.listen(port, host, () => {
          server.off("error", rejectListen);
          // A later socket-level error must not become an uncaught exception.
          server.on("error", (error) => log(`http server error: ${error.message}`));
          const address = server.address() as AddressInfo;
          resolveListen({ host: address.address, port: address.port });
        });
      });
    },
    close() {
      const closers = Array.from(sseClients.values(), (clients) => Array.from(clients)).flat();
      sseClients.clear();
      for (const close of closers) close();
      for (const session of store.list()) session.activeTurn?.controller.abort();
      return new Promise((resolveClose) => {
        server.close(() => resolveClose());
        server.closeAllConnections();
      });
    },
  };
}

function extractPrompt(body: unknown): string | null {
  if (body === null || typeof body !== "object") return null;
  const record = body as { readonly prompt?: unknown; readonly messages?: unknown };
  if (typeof record.prompt === "string" && record.prompt.trim() !== "") {
    return record.prompt;
  }
  if (Array.isArray(record.messages)) {
    const users = record.messages.filter(
      (message): message is { readonly role: "user"; readonly content: string } =>
        message !== null &&
        typeof message === "object" &&
        (message as { role?: unknown }).role === "user" &&
        typeof (message as { content?: unknown }).content === "string",
    );
    const last = users[users.length - 1];
    if (last !== undefined && last.content.trim() !== "") return last.content;
  }
  return null;
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for await (const chunk of request) {
      const buffer = chunk as Buffer;
      size += buffer.byteLength;
      if (size > MAX_BODY_BYTES) {
        throw new HttpError(413, "BODY_TOO_LARGE", `request body exceeds ${MAX_BODY_BYTES} bytes`);
      }
      chunks.push(buffer);
    }
  } catch (error) {
    if (error instanceof HttpError) throw error;
    // The client went away mid-body; not a server fault worth a stack trace.
    throw new HttpError(400, "BODY_READ_FAILED", `request body could not be read: ${error instanceof Error ? error.message : String(error)}`);
  }
  const text = Buffer.concat(chunks).toString("utf8").trim();
  if (text === "") return {};
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new HttpError(400, "INVALID_JSON", "request body is not valid JSON");
  }
}

function sendJson(response: ServerResponse, status: number, value: unknown): void {
  const body = JSON.stringify(value);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
  });
  response.end(body);
}

async function serveStatic(response: ServerResponse, root: string, requestPath: string, headOnly: boolean): Promise<void> {
  let relative: string;
  try {
    relative = requestPath === "/" ? "index.html" : decodeURIComponent(requestPath.slice(1));
  } catch {
    throw new HttpError(400, "BAD_PATH", "malformed percent-encoding in path");
  }
  const target = resolve(root, relative);
  if (target !== root && !target.startsWith(root + sep)) {
    throw new HttpError(404, "NOT_FOUND", "not found");
  }
  let info;
  try {
    info = await stat(target);
  } catch {
    throw new HttpError(404, "NOT_FOUND", `no static file for ${requestPath}`);
  }
  if (!info.isFile()) {
    throw new HttpError(404, "NOT_FOUND", `no static file for ${requestPath}`);
  }
  const contentType = STATIC_CONTENT_TYPES[extname(target).toLowerCase()] ?? "application/octet-stream";
  const body = await readFile(target);
  response.writeHead(200, {
    "content-type": contentType,
    "content-length": body.byteLength,
    "cache-control": "no-cache",
  });
  response.end(headOnly ? undefined : body);
}
