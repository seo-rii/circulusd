import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  decodeCanonicalCbor,
  encodeCanonicalCbor,
  type NormalizedValue,
} from "@circulusd/protocol-types";

import worker from "../src/host/worker.ts";

const INGRESS_PATH = "/circulusd/state/v1/session-events:read";
const INGRESS_CONTENT_TYPE = "application/vnd.circulusd.state-ingress+cbor";
const INGRESS_PROTOCOL = "circulus.state-ingress.v1alpha1";
const INGRESS_SCHEMA_DIGEST =
  "sha256:6365dfa4e6e73b349508a46688cfcaacdeacece11cd11ed2d7f3e40af49ad3ee";
const HOST_PROTOCOL = "circulus.v1alpha1";
const HOST_SCHEMA_DIGEST =
  "sha256:58371a0cde5b6e833a492ee580e02d9ae80a9b311ec2cda116475b51417ba164";
const HOST_CONTENT_TYPE = INGRESS_CONTENT_TYPE;
const CURRENT_KEY_ID = "state-current-1";
const PREVIOUS_KEY_ID = "state-previous-1";
const CURRENT_KEY = new Uint8Array(32).fill(0x31);
const PREVIOUS_KEY = new Uint8Array(48).fill(0x42);
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const CANONICAL_BASE32_FINAL = "AEIMQUY4";
const REQUEST_SIGNATURE_HEADER = "x-circulus-state-signature";
const KEY_ID_HEADER = "x-circulus-state-key-id";

interface HostRequest {
  readonly protocol: string;
  readonly major: number;
  readonly minor: number;
  readonly schemaDigest: string;
  readonly requestId: string;
  readonly payload: {
    readonly authority: {
      readonly serviceBinding: string;
      readonly tenantId: string;
      readonly actorUserId: string;
      readonly subjectKind: string;
      readonly subjectId: string;
      readonly roles: readonly string[];
      readonly permissions: readonly string[];
      readonly authorizationGeneration: number;
      readonly currentAuthorizationGeneration: number;
      readonly issuedAt: number;
      readonly expiresAt: number;
    };
    readonly now: number;
    readonly afterSequence: number;
    readonly limit: number;
  };
}

interface SessionStub {
  readSessionEvents(request: unknown): Promise<unknown>;
  initializeSession?(request: unknown): Promise<unknown>;
  executeSessionCommand?(request: unknown): Promise<unknown>;
  readSession?(request: unknown): Promise<unknown>;
}

interface TestEnvironment {
  CIRCULUSD_STATE_INGRESS_CURRENT_KEY_ID?: string;
  CIRCULUSD_STATE_INGRESS_CURRENT_KEY?: string;
  CIRCULUSD_STATE_INGRESS_PREVIOUS_KEY_ID?: string;
  CIRCULUSD_STATE_INGRESS_PREVIOUS_KEY?: string;
  SESSION_CELL: {
    getByName(name: string): SessionStub;
  };
}

type IngressPayload = ReturnType<typeof ingressPayload>;

function identity(kind: "req" | "tenant" | "subject" | "sess", index = 0): string {
  const high = BASE32[Math.floor(index / CANONICAL_BASE32_FINAL.length)] ?? "A";
  const low = CANONICAL_BASE32_FINAL[index % CANONICAL_BASE32_FINAL.length] ?? "A";
  return `${kind}_${"A".repeat(24)}${high}${low}`;
}

function ingressPayload(index = 0, sentAtUnixMs = Date.now()) {
  return {
    protocol: INGRESS_PROTOCOL,
    major: 1,
    minor: 0,
    schemaDigest: INGRESS_SCHEMA_DIGEST,
    requestId: identity("req", index),
    sentAtUnixMs,
    tenantId: identity("tenant"),
    actorSubjectId: identity("subject"),
    sessionId: identity("sess"),
    expectedAuthorizationGeneration: 7,
    afterSequence: index,
    limit: 16,
  };
}

function text(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function hex(value: Uint8Array): string {
  return [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function decodeHex(value: string): Uint8Array {
  const result = new Uint8Array(value.length / 2);
  for (let index = 0; index < value.length; index += 2) {
    result[index / 2] = Number.parseInt(value.slice(index, index + 2), 16);
  }
  return result;
}

function replaceOneByteFieldValue(
  body: Uint8Array,
  field: string,
  replacement: Uint8Array,
): Uint8Array {
  const encodedField = encodeCanonicalCbor(field);
  const fieldIndex = body.findIndex((_, index) =>
    encodedField.every((byte, offset) => body[index + offset] === byte)
  );
  expect(fieldIndex).toBeGreaterThanOrEqual(0);
  const valueIndex = fieldIndex + encodedField.byteLength;
  expect(body[valueIndex]).toBeLessThan(24);
  return new Uint8Array([
    ...body.slice(0, valueIndex),
    ...replacement,
    ...body.slice(valueIndex + 1),
  ]);
}

function lengthPrefixed(parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((total, part) => total + 4 + part.byteLength, 0);
  const framed = new Uint8Array(length);
  const view = new DataView(framed.buffer);
  let offset = 0;
  for (const part of parts) {
    view.setUint32(offset, part.byteLength, false);
    offset += 4;
    framed.set(part, offset);
    offset += part.byteLength;
  }
  return framed;
}

async function hmac(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { hash: "SHA-256", name: "HMAC" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, message));
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", value));
}

async function directionalKey(
  rootKey: Uint8Array,
  direction: "request" | "response",
): Promise<Uint8Array> {
  return hmac(rootKey, text(`circulusd.state-ingress.key.${direction}.v1\0`));
}

async function requestSignature(
  body: Uint8Array,
  keyId = CURRENT_KEY_ID,
  rootKey = CURRENT_KEY,
  method = "POST",
  path = INGRESS_PATH,
): Promise<string> {
  const requestKey = await directionalKey(rootKey, "request");
  return hex(await hmac(requestKey, lengthPrefixed([
    text("circulusd.state-ingress.request.v1"),
    text(keyId),
    text(method),
    text(path),
    await sha256(body),
  ])));
}

async function responseSignature(
  body: Uint8Array,
  requestBody: Uint8Array,
  status: number,
  requestId: string,
  keyId = CURRENT_KEY_ID,
  rootKey = CURRENT_KEY,
): Promise<string> {
  const responseKey = await directionalKey(rootKey, "response");
  return hex(await hmac(responseKey, lengthPrefixed([
    text("circulusd.state-ingress.response.v1"),
    text(keyId),
    text(requestId),
    await sha256(requestBody),
    text(String(status)),
    text(HOST_CONTENT_TYPE),
    await sha256(body),
  ])));
}

async function requestFromBytes(
  body: Uint8Array,
  options: {
    readonly keyId?: string;
    readonly rootKey?: Uint8Array;
    readonly method?: string;
    readonly path?: string;
    readonly query?: string;
    readonly contentType?: string;
    readonly contentEncoding?: string;
    readonly signature?: string | null;
    readonly contentLength?: string;
  } = {},
): Promise<Request> {
  const keyId = options.keyId ?? CURRENT_KEY_ID;
  const method = options.method ?? "POST";
  const path = options.path ?? INGRESS_PATH;
  const headers = new Headers();
  headers.set("content-type", options.contentType ?? INGRESS_CONTENT_TYPE);
  headers.set(KEY_ID_HEADER, keyId);
  if (options.contentEncoding !== undefined) {
    headers.set("content-encoding", options.contentEncoding);
  }
  if (options.contentLength !== undefined) {
    headers.set("content-length", options.contentLength);
  }
  const signature = options.signature === undefined
    ? await requestSignature(body, keyId, options.rootKey ?? CURRENT_KEY, method, path)
    : options.signature;
  if (signature !== null) {
    headers.set(REQUEST_SIGNATURE_HEADER, signature);
  }
  const init: RequestInit = { method, headers };
  if (method !== "GET" && method !== "HEAD") {
    init.body = body;
  }
  return new Request(
    `http://127.0.0.1:8787${path}${options.query ?? ""}`,
    init,
  );
}

async function signedRequest(
  payload: IngressPayload = ingressPayload(),
  options: Parameters<typeof requestFromBytes>[1] = {},
): Promise<{ readonly request: Request; readonly body: Uint8Array }> {
  const body = encodeCanonicalCbor(payload);
  return { request: await requestFromBytes(body, options), body };
}

function hostSuccess(requestId: string, lastEventSequence = 0) {
  return {
    protocol: HOST_PROTOCOL,
    major: 1,
    minor: 0,
    schemaDigest: HOST_SCHEMA_DIGEST,
    requestId,
    payload: {
      ok: true,
      result: {
        snapshot: {
          sessionId: identity("sess"),
          activeTurnId: null,
          turnStatus: null,
          lastEventSequence,
        },
        events: [],
      },
    },
  };
}

function hostFailure(requestId: string, code: string, message: string) {
  return {
    protocol: HOST_PROTOCOL,
    major: 1,
    minor: 0,
    schemaDigest: HOST_SCHEMA_DIGEST,
    requestId,
    payload: { ok: false, error: { code, message } },
  };
}

function environment(
  stub: SessionStub,
  names: string[] = [],
  overrides: Partial<TestEnvironment> = {},
): TestEnvironment {
  return {
    CIRCULUSD_STATE_INGRESS_CURRENT_KEY_ID: CURRENT_KEY_ID,
    CIRCULUSD_STATE_INGRESS_CURRENT_KEY: hex(CURRENT_KEY),
    SESSION_CELL: {
      getByName: (name) => {
        names.push(name);
        return stub;
      },
    },
    ...overrides,
  };
}

async function invoke(request: Request, env: TestEnvironment): Promise<Response> {
  return worker.fetch(request, env as never);
}

async function signedResponse(
  response: Response,
  requestBody: Uint8Array,
  requestId: string,
  rootKey = CURRENT_KEY,
  keyId = CURRENT_KEY_ID,
): Promise<NormalizedValue> {
  const body = new Uint8Array(await response.arrayBuffer());
  expect(response.headers.get("content-type")).toBe(HOST_CONTENT_TYPE);
  expect(response.headers.get(KEY_ID_HEADER)).toBe(keyId);
  expect(response.headers.get(REQUEST_SIGNATURE_HEADER)).toBe(
    await responseSignature(body, requestBody, response.status, requestId, keyId, rootKey),
  );
  return decodeCanonicalCbor(body);
}

function expectUnsigned(response: Response): void {
  expect(response.headers.has(KEY_ID_HEADER)).toBe(false);
  expect(response.headers.has(REQUEST_SIGNATURE_HEADER)).toBe(false);
}

describe("authenticated state-app ingress", () => {
  it("routes only one authenticated public-event read and derives all trusted fields", async () => {
    const names: string[] = [];
    let captured: HostRequest | undefined;
    const { request, body } = await signedRequest();
    const before = Date.now();
    const response = await invoke(request, environment({
      readSessionEvents: async (unknownRequest) => {
        captured = structuredClone(unknownRequest) as HostRequest;
        return hostSuccess(captured.requestId);
      },
    }, names));
    const after = Date.now();

    expect(response.status).toBe(200);
    expect(names).toEqual([
      JSON.stringify([
        "circulusd.state-app.cell",
        1,
        "session",
        identity("tenant"),
        identity("sess"),
      ]),
    ]);
    expect(captured).toBeDefined();
    expect(captured).toEqual({
      protocol: HOST_PROTOCOL,
      major: 1,
      minor: 0,
      schemaDigest: HOST_SCHEMA_DIGEST,
      requestId: identity("req"),
      payload: {
        authority: {
          serviceBinding: "state",
          tenantId: identity("tenant"),
          actorUserId: identity("subject"),
          subjectKind: "session",
          subjectId: identity("sess"),
          roles: [],
          permissions: ["session.read"],
          authorizationGeneration: 7,
          currentAuthorizationGeneration: 7,
          issuedAt: captured?.payload.now,
          expiresAt: (captured?.payload.now ?? 0) + 1,
        },
        now: captured?.payload.now,
        afterSequence: 0,
        limit: 16,
      },
    });
    expect(captured!.payload.now).toBeGreaterThanOrEqual(before);
    expect(captured!.payload.now).toBeLessThanOrEqual(after);
    expect(await signedResponse(response, body, identity("req"))).toEqual(
      hostSuccess(identity("req")),
    );
  });

  it.each([
    ["wrong method", { method: "PUT" }, 405],
    ["wrong path", { path: "/circulusd/state/v1/session/read" }, 404],
    ["query", { query: "?operation=session.read-events" }, 404],
    ["wrong content type", { contentType: "application/cbor" }, 415],
    ["content type parameter", { contentType: `${INGRESS_CONTENT_TYPE}; charset=utf-8` }, 415],
    ["content encoding", { contentEncoding: "gzip" }, 415],
  ] as const)("rejects %s before resolving a Durable Object", async (_name, options, status) => {
    let calls = 0;
    const { request } = await signedRequest(ingressPayload(), options);
    const response = await invoke(request, environment({
      readSessionEvents: async () => {
        calls += 1;
        return hostSuccess(identity("req"));
      },
    }));
    expect(response.status).toBe(status);
    expect(calls).toBe(0);
    expectUnsigned(response);
  });

  it.each([
    ["missing signature", { signature: null }],
    ["short signature", { signature: "00" }],
    ["uppercase signature", { signature: "AA".repeat(32) }],
    ["bad signature", { signature: "00".repeat(32) }],
    ["combined signature", { signature: `${"00".repeat(32)},${"11".repeat(32)}` }],
    ["unknown key", { keyId: "state-unknown-1", rootKey: PREVIOUS_KEY }],
    ["combined key id", { keyId: `${CURRENT_KEY_ID},${PREVIOUS_KEY_ID}` }],
  ] as const)("rejects %s without parsing an authority", async (_name, options) => {
    let calls = 0;
    const { request } = await signedRequest(ingressPayload(), options);
    const response = await invoke(request, environment({
      readSessionEvents: async () => {
        calls += 1;
        return hostSuccess(identity("req"));
      },
    }));
    expect(response.status).toBe(401);
    expect(calls).toBe(0);
    expectUnsigned(response);
  });

  it.each([
    ["short current key", {
      CIRCULUSD_STATE_INGRESS_CURRENT_KEY: hex(CURRENT_KEY.slice(0, 31)),
    }],
    ["missing current key", {
      CIRCULUSD_STATE_INGRESS_CURRENT_KEY: undefined,
    }],
    ["half previous key", {
      CIRCULUSD_STATE_INGRESS_PREVIOUS_KEY_ID: PREVIOUS_KEY_ID,
    }],
    ["duplicate key id", {
      CIRCULUSD_STATE_INGRESS_PREVIOUS_KEY_ID: CURRENT_KEY_ID,
      CIRCULUSD_STATE_INGRESS_PREVIOUS_KEY: hex(PREVIOUS_KEY),
    }],
  ] as const)("fails closed for %s configuration", async (_name, overrides) => {
    let calls = 0;
    const { request } = await signedRequest();
    const response = await invoke(request, environment({
      readSessionEvents: async () => {
        calls += 1;
        return hostSuccess(identity("req"));
      },
    }, [], overrides));
    expect(response.status).toBe(503);
    expect(calls).toBe(0);
    expectUnsigned(response);
  });

  it.each([
    ["trailing bytes", new Uint8Array([...encodeCanonicalCbor(ingressPayload()), 0])],
    ["duplicate map key", decodeHex("a2616100616101")],
    ["non-minimal text length", decodeHex("a178016100")],
    ["truncated value", decodeHex("a1")],
    [
      "unsafe generation",
      replaceOneByteFieldValue(
        encodeCanonicalCbor(ingressPayload()),
        "expectedAuthorizationGeneration",
        decodeHex("1b0020000000000000"),
      ),
    ],
    [
      "unsafe cursor",
      replaceOneByteFieldValue(
        encodeCanonicalCbor(ingressPayload()),
        "afterSequence",
        decodeHex("1b0020000000000000"),
      ),
    ],
  ])("authenticates raw bytes, then rejects %s canonical CBOR", async (_name, rawBody) => {
    let calls = 0;
    const request = await requestFromBytes(rawBody);
    const response = await invoke(request, environment({
      readSessionEvents: async () => {
        calls += 1;
        return hostSuccess(identity("req"));
      },
    }));
    expect(response.status).toBe(400);
    expect(calls).toBe(0);
    const decoded = await signedResponse(response, rawBody, "invalid-request");
    expect(decoded).toMatchObject({
      requestId: "invalid-request",
      payload: { ok: false, error: { code: "INVALID_ARGUMENT" } },
    });
  });

  it.each([
    ["wrong protocol", { protocol: "circulus.state-ingress.v1" }],
    ["wrong major", { major: 2 }],
    ["wrong minor", { minor: 1 }],
    ["wrong digest", { schemaDigest: `sha256:${"0".repeat(64)}` }],
    ["invalid request id", { requestId: "request-1" }],
    ["invalid tenant", { tenantId: identity("subject") }],
    ["invalid actor", { actorSubjectId: identity("tenant") }],
    ["invalid session", { sessionId: identity("req") }],
    ["zero generation", { expectedAuthorizationGeneration: 0 }],
    ["negative cursor", { afterSequence: -1 }],
    ["zero limit", { limit: 0 }],
    ["oversize limit", { limit: 257 }],
    ["stale timestamp", { sentAtUnixMs: Date.now() - 60_001 }],
    ["future timestamp", { sentAtUnixMs: Date.now() + 60_001 }],
    ["caller operation", { operation: "session.read-events" }],
    ["caller role", { roles: ["platform-admin"] }],
    ["caller permission", { permissions: ["session.read"] }],
    ["caller current generation", { currentAuthorizationGeneration: 7 }],
    ["caller time", { now: Date.now() }],
    ["caller cell", { cellName: "physical:attacker" }],
    ["caller method", { method: "session.execute" }],
    ["caller inner envelope", { payload: { operation: "session.execute" } }],
  ])("rejects semantic request field case: %s", async (_name, override) => {
    let calls = 0;
    const payload = { ...ingressPayload(), ...override } as IngressPayload;
    const { request, body } = await signedRequest(payload);
    const response = await invoke(request, environment({
      readSessionEvents: async () => {
        calls += 1;
        return hostSuccess(identity("req"));
      },
    }));
    expect(response.status).toBe(400);
    expect(calls).toBe(0);
    expect(await signedResponse(response, body, payload.requestId)).toMatchObject({
      payload: { ok: false, error: { code: "INVALID_ARGUMENT" } },
    });
  });

  it("rejects a missing exact request field", async () => {
    const payload = { ...ingressPayload() } as Record<string, unknown>;
    delete payload.limit;
    const body = encodeCanonicalCbor(payload);
    let calls = 0;
    const response = await invoke(await requestFromBytes(body), environment({
      readSessionEvents: async () => {
        calls += 1;
        return hostSuccess(identity("req"));
      },
    }));
    expect(response.status).toBe(400);
    expect(calls).toBe(0);
    expect(await signedResponse(response, body, identity("req"))).toMatchObject({
      payload: { ok: false, error: { code: "INVALID_ARGUMENT" } },
    });
  });

  it("caps declared and streamed bodies before decode or Durable Object routing", async () => {
    let calls = 0;
    const stub: SessionStub = {
      readSessionEvents: async () => {
        calls += 1;
        return hostSuccess(identity("req"));
      },
    };
    const canonical = encodeCanonicalCbor(ingressPayload());
    const declared = await requestFromBytes(canonical, { contentLength: "4097" });
    const declaredResponse = await invoke(declared, environment(stub));
    expect(declaredResponse.status).toBe(413);
    expectUnsigned(declaredResponse);

    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(3_000));
        controller.enqueue(new Uint8Array(1_097));
        controller.close();
      },
    });
    const streamed = new Request(`http://127.0.0.1:8787${INGRESS_PATH}`, {
      method: "POST",
      headers: {
        "content-type": INGRESS_CONTENT_TYPE,
        [KEY_ID_HEADER]: CURRENT_KEY_ID,
        [REQUEST_SIGNATURE_HEADER]: "00".repeat(32),
      },
      body: stream,
      duplex: "half",
    } as RequestInit & { duplex: "half" });
    const streamedResponse = await invoke(streamed, environment(stub));
    expect(streamedResponse.status).toBe(413);
    expectUnsigned(streamedResponse);
    expect(calls).toBe(0);
  });

  it("accepts a bounded previous key, signs with that exact key, and rejects it after removal", async () => {
    const env = environment({
      readSessionEvents: async (request) => hostSuccess((request as HostRequest).requestId),
    }, [], {
      CIRCULUSD_STATE_INGRESS_PREVIOUS_KEY_ID: PREVIOUS_KEY_ID,
      CIRCULUSD_STATE_INGRESS_PREVIOUS_KEY: hex(PREVIOUS_KEY),
    });
    const first = await signedRequest(ingressPayload(), {
      keyId: PREVIOUS_KEY_ID,
      rootKey: PREVIOUS_KEY,
    });
    const response = await invoke(first.request, env);
    expect(response.status).toBe(200);
    expect(await signedResponse(
      response,
      first.body,
      identity("req"),
      PREVIOUS_KEY,
      PREVIOUS_KEY_ID,
    )).toEqual(hostSuccess(identity("req")));

    delete env.CIRCULUSD_STATE_INGRESS_PREVIOUS_KEY_ID;
    delete env.CIRCULUSD_STATE_INGRESS_PREVIOUS_KEY;
    const second = await signedRequest(ingressPayload(), {
      keyId: PREVIOUS_KEY_ID,
      rootKey: PREVIOUS_KEY,
    });
    const rejected = await invoke(second.request, env);
    expect(rejected.status).toBe(401);
    expectUnsigned(rejected);
  });

  it("captures an immutable keyring for an in-flight response during rotation", async () => {
    let release!: () => void;
    let reached!: () => void;
    const waiting = new Promise<void>((resolve) => {
      release = resolve;
    });
    const entered = new Promise<void>((resolve) => {
      reached = resolve;
    });
    const env = environment({
      readSessionEvents: async (request) => {
        reached();
        await waiting;
        return hostSuccess((request as HostRequest).requestId);
      },
    });
    const signed = await signedRequest();
    const pending = invoke(signed.request, env);
    await entered;
    env.CIRCULUSD_STATE_INGRESS_CURRENT_KEY_ID = "state-next-1";
    env.CIRCULUSD_STATE_INGRESS_CURRENT_KEY = hex(PREVIOUS_KEY);
    release();
    const response = await pending;
    expect(await signedResponse(response, signed.body, identity("req"))).toEqual(
      hostSuccess(identity("req")),
    );
  });

  it("sanitizes authenticated Durable Object failures and malformed responses", async () => {
    const cases: readonly [string, SessionStub, number, string, string][] = [
      [
        "host failure message",
        {
          readSessionEvents: async (request) => hostFailure(
            (request as HostRequest).requestId,
            "PERMISSION_DENIED",
            "secret ACL row 42",
          ),
        },
        200,
        "PERMISSION_DENIED",
        "The operation is not permitted.",
      ],
      [
        "thrown exception",
        {
          readSessionEvents: async () => {
            throw new Error("database password hunter2");
          },
        },
        502,
        "INTERNAL_ERROR",
        "The operation could not be completed.",
      ],
      [
        "wrong response request ID",
        {
          readSessionEvents: async () => hostSuccess(identity("req", 1)),
        },
        502,
        "INTERNAL_ERROR",
        "The operation could not be completed.",
      ],
    ];
    for (const [_name, stub, status, code, message] of cases) {
      const signed = await signedRequest();
      const response = await invoke(signed.request, environment(stub));
      expect(response.status).toBe(status);
      const decoded = await signedResponse(response, signed.body, identity("req"));
      expect(decoded).toMatchObject({
        requestId: identity("req"),
        payload: { ok: false, error: { code, message } },
      });
      expect(JSON.stringify(decoded)).not.toMatch(/secret|password|hunter2/i);
    }
  });

  it("turns an authenticated oversized Host response into a signed bounded failure", async () => {
    const signed = await signedRequest();
    const response = await invoke(signed.request, environment({
      readSessionEvents: async (request) => ({
        ...hostSuccess((request as HostRequest).requestId),
        payload: { ok: true, result: "x".repeat(1_200_000) },
      }),
    }));
    expect(response.status).toBe(502);
    expect(await signedResponse(response, signed.body, identity("req"))).toMatchObject({
      payload: { ok: false, error: { code: "RESOURCE_EXHAUSTED" } },
    });
  });

  it("allows exact replay only as two read-only calls and never reaches mutation methods", async () => {
    const calls = { events: 0, initialize: 0, execute: 0, read: 0 };
    const stub: SessionStub = {
      readSessionEvents: async (request) => {
        calls.events += 1;
        return hostSuccess((request as HostRequest).requestId);
      },
      initializeSession: async () => {
        calls.initialize += 1;
      },
      executeSessionCommand: async () => {
        calls.execute += 1;
      },
      readSession: async () => {
        calls.read += 1;
      },
    };
    const payload = ingressPayload();
    const body = encodeCanonicalCbor(payload);
    const first = await invoke(await requestFromBytes(body), environment(stub));
    const second = await invoke(await requestFromBytes(body), environment(stub));
    expect(first.status).toBe(200);
    expect(second.status).toBe(200);

    const hostileBody = encodeCanonicalCbor({
      ...payload,
      operation: "session.execute",
      method: "executeSessionCommand",
    });
    const hostile = await invoke(await requestFromBytes(hostileBody), environment(stub));
    expect(hostile.status).toBe(400);
    expect(calls).toEqual({ events: 2, initialize: 0, execute: 0, read: 0 });
  });

  it("linearizes the Session generation fence before or after a concurrent rotation", async () => {
    let generation = 7;
    let release!: () => void;
    let reached!: () => void;
    const waiting = new Promise<void>((resolve) => {
      release = resolve;
    });
    const entered = new Promise<void>((resolve) => {
      reached = resolve;
    });
    const staleStub: SessionStub = {
      readSessionEvents: async (unknownRequest) => {
        const request = unknownRequest as HostRequest;
        reached();
        await waiting;
        return request.payload.authority.currentAuthorizationGeneration === generation
          ? hostSuccess(request.requestId)
          : hostFailure(
            request.requestId,
            "STALE_GENERATION",
            "The supplied generation is stale.",
          );
      },
    };
    const staleRequest = await signedRequest();
    const stalePending = invoke(staleRequest.request, environment(staleStub));
    await entered;
    generation = 8;
    release();
    const staleResponse = await stalePending;
    expect(await signedResponse(
      staleResponse,
      staleRequest.body,
      identity("req"),
    )).toMatchObject({
      payload: { ok: false, error: { code: "STALE_GENERATION" } },
    });

    generation = 7;
    const currentRequest = await signedRequest();
    const currentResponse = await invoke(currentRequest.request, environment({
      readSessionEvents: async (unknownRequest) => {
        const request = unknownRequest as HostRequest;
        return request.payload.authority.currentAuthorizationGeneration === generation
          ? hostSuccess(request.requestId)
          : hostFailure(
            request.requestId,
            "STALE_GENERATION",
            "The supplied generation is stale.",
          );
      },
    }));
    generation = 8;
    expect(await signedResponse(
      currentResponse,
      currentRequest.body,
      identity("req"),
    )).toMatchObject({ payload: { ok: true } });
  });

  it("keeps request, body digest, response, and signature isolated across 64 concurrent reads", async () => {
    const seen = new Set<string>();
    const env = environment({
      readSessionEvents: async (unknownRequest) => {
        const request = unknownRequest as HostRequest;
        seen.add(request.requestId);
        await Promise.resolve();
        return hostSuccess(request.requestId, request.payload.afterSequence);
      },
    });
    const inputs = await Promise.all(
      Array.from({ length: 64 }, async (_, index) => signedRequest(ingressPayload(index))),
    );
    const responses = await Promise.all(inputs.map(({ request }) => invoke(request, env)));
    const decoded = await Promise.all(responses.map((response, index) => signedResponse(
      response,
      inputs[index]!.body,
      identity("req", index),
    )));
    expect(seen).toHaveLength(64);
    for (const [index, response] of decoded.entries()) {
      expect(response).toMatchObject({
        requestId: identity("req", index),
        payload: {
          ok: true,
          result: { snapshot: { lastEventSequence: index } },
        },
      });
    }
  });

  it("pins canonical request/response bytes and direction-separated MACs in a shared golden", async () => {
    const fixture = JSON.parse(readFileSync(new URL(
      "../../../packages/protocol-types/fixtures/state-app-ingress-v1alpha1.json",
      import.meta.url,
    ), "utf8")) as {
      readonly keyId: string;
      readonly rootKeyHex: string;
      readonly request: IngressPayload;
      readonly requestCborHex: string;
      readonly requestMacHex: string;
      readonly response: NormalizedValue;
      readonly responseCborHex: string;
      readonly responseMacHex: string;
    };
    const rootKey = decodeHex(fixture.rootKeyHex);
    const requestBody = encodeCanonicalCbor(fixture.request);
    const responseBody = encodeCanonicalCbor(fixture.response);
    expect(hex(requestBody)).toBe(fixture.requestCborHex);
    expect(await requestSignature(requestBody, fixture.keyId, rootKey)).toBe(
      fixture.requestMacHex,
    );
    expect(hex(responseBody)).toBe(fixture.responseCborHex);
    expect(await responseSignature(
      responseBody,
      requestBody,
      200,
      fixture.request.requestId,
      fixture.keyId,
      rootKey,
    )).toBe(fixture.responseMacHex);
    expect(fixture.responseMacHex).not.toBe(fixture.requestMacHex);
  });
});
