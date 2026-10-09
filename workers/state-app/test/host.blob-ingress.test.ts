import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  decodeCanonicalCbor,
  digestBytes,
  encodeCanonicalCbor,
  type Digest,
  type NormalizedValue,
} from "@circulusd/protocol-types";

import worker from "../src/host/worker.ts";

const INGRESS_PATH = "/circulusd/state/v1/session-blob:read";
const INGRESS_CONTENT_TYPE = "application/vnd.circulusd.state-blob-ingress+cbor";
const INGRESS_PROTOCOL = "circulus.state-blob-ingress.v1alpha1";
const INGRESS_SCHEMA_DIGEST =
  "sha256:43de3ec79f1eb1a1d78e519e24b741630ea2f5bee0cf2ce9e02ee4416dd67aab";
const READ_EVENTS_PATH = "/circulusd/state/v1/session-events:read";
const READ_EVENTS_CONTENT_TYPE = "application/vnd.circulusd.state-ingress+cbor";
const REQUEST_MAC_DOMAIN = "circulusd.state-blob-ingress.request.v1";
const RESPONSE_MAC_DOMAIN = "circulusd.state-blob-ingress.response.v1";
const READ_EVENTS_REQUEST_MAC_DOMAIN = "circulusd.state-ingress.request.v1";
const HOST_PROTOCOL = "circulus.v1alpha1";
// session.read-blob host RPC contract digest (src/host/rpc.ts).
const HOST_SCHEMA_DIGEST =
  "sha256:ecde7c59aafe4e2ce0e885be977535619401085346b47e59c7a5487de7b45f70";
const CURRENT_KEY_ID = "state-current-1";
const CURRENT_KEY = new Uint8Array(32).fill(0x31);
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const CANONICAL_BASE32_FINAL = "AEIMQUY4";
const SIGNATURE_HEADER = "x-circulus-state-signature";
const KEY_ID_HEADER = "x-circulus-state-key-id";
const MAX_BLOB_BYTES = 4 * 1_048_576;
const ENVELOPE_HEADROOM_BYTES = 65_536;
const ZERO_DIGEST = `sha256:${"0".repeat(64)}`;
const BLOB = new TextEncoder().encode("hydrated checkpoint payload bytes");

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
    readonly digest: string;
  };
}

interface SessionStub {
  readSessionBlob?(request: unknown): Promise<unknown>;
  readSessionEvents?(request: unknown): Promise<unknown>;
  initializeSession?(request: unknown): Promise<unknown>;
  executeSessionCommand?(request: unknown): Promise<unknown>;
  readSession?(request: unknown): Promise<unknown>;
}

interface TestEnvironment {
  CIRCULUSD_STATE_INGRESS_CURRENT_KEY_ID?: string;
  CIRCULUSD_STATE_INGRESS_CURRENT_KEY?: string;
  CIRCULUSD_STATE_DISPATCH_START_CURRENT_KEY_ID?: string;
  CIRCULUSD_STATE_DISPATCH_START_CURRENT_KEY?: string;
  SESSION_CELL: {
    getByName(name: string): SessionStub;
  };
}

type IngressPayload = Record<string, NormalizedValue>;

function identity(kind: "req" | "tenant" | "subject" | "sess", index = 0): string {
  const high = BASE32[Math.floor(index / CANONICAL_BASE32_FINAL.length)] ?? "A";
  const low = CANONICAL_BASE32_FINAL[index % CANONICAL_BASE32_FINAL.length] ?? "A";
  return `${kind}_${"A".repeat(24)}${high}${low}`;
}

async function blobDigest(bytes: Uint8Array = BLOB): Promise<Digest> {
  return digestBytes(bytes);
}

async function ingressPayload(index = 0, sentAtUnixMs = Date.now()): Promise<IngressPayload> {
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
    digest: await blobDigest(),
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
  options: {
    readonly keyId?: string;
    readonly rootKey?: Uint8Array;
    readonly method?: string;
    readonly path?: string;
    readonly domain?: string;
  } = {},
): Promise<string> {
  const requestKey = await directionalKey(options.rootKey ?? CURRENT_KEY, "request");
  return hex(await hmac(requestKey, lengthPrefixed([
    text(options.domain ?? REQUEST_MAC_DOMAIN),
    text(options.keyId ?? CURRENT_KEY_ID),
    text(options.method ?? "POST"),
    text(options.path ?? INGRESS_PATH),
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
    text(RESPONSE_MAC_DOMAIN),
    text(keyId),
    text(requestId),
    await sha256(requestBody),
    text(String(status)),
    text(INGRESS_CONTENT_TYPE),
    await sha256(body),
  ])));
}

async function requestFromBytes(
  body: Uint8Array,
  options: {
    readonly keyId?: string;
    readonly rootKey?: Uint8Array;
    readonly path?: string;
    readonly contentType?: string;
    readonly signature?: string;
  } = {},
): Promise<Request> {
  const keyId = options.keyId ?? CURRENT_KEY_ID;
  const path = options.path ?? INGRESS_PATH;
  const headers = new Headers();
  headers.set("content-type", options.contentType ?? INGRESS_CONTENT_TYPE);
  headers.set(KEY_ID_HEADER, keyId);
  headers.set(
    SIGNATURE_HEADER,
    options.signature ??
      await requestSignature(body, { keyId, rootKey: options.rootKey, path }),
  );
  return new Request(`http://127.0.0.1:8787${path}`, { method: "POST", headers, body });
}

async function signedRequest(
  payload: IngressPayload,
  options: Parameters<typeof requestFromBytes>[1] = {},
): Promise<{ readonly request: Request; readonly body: Uint8Array }> {
  const body = encodeCanonicalCbor(payload);
  return { request: await requestFromBytes(body, options), body };
}

function hostSuccess(requestId: string, result: NormalizedValue) {
  return {
    protocol: HOST_PROTOCOL,
    major: 1,
    minor: 0,
    schemaDigest: HOST_SCHEMA_DIGEST,
    requestId,
    payload: { ok: true, result },
  };
}

async function hydratedResult(bytes: Uint8Array = BLOB): Promise<NormalizedValue> {
  return { digest: await blobDigest(bytes), encodedBytes: bytes.byteLength, bytes };
}

function environment(
  stub: SessionStub,
  names: string[] = [],
  overrides: Partial<TestEnvironment> = {},
): TestEnvironment {
  const guarded: SessionStub = {
    readSessionEvents: async () => {
      throw new Error("readSessionEvents must not be reached by a blob read");
    },
    initializeSession: async () => {
      throw new Error("initializeSession must not be reached by a blob read");
    },
    executeSessionCommand: async () => {
      throw new Error("executeSessionCommand must not be reached by a blob read");
    },
    readSession: async () => {
      throw new Error("readSession must not be reached by a blob read");
    },
    ...stub,
  };
  return {
    CIRCULUSD_STATE_INGRESS_CURRENT_KEY_ID: CURRENT_KEY_ID,
    CIRCULUSD_STATE_INGRESS_CURRENT_KEY: hex(CURRENT_KEY),
    SESSION_CELL: {
      getByName: (name) => {
        names.push(name);
        return guarded;
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
): Promise<NormalizedValue> {
  const body = new Uint8Array(await response.arrayBuffer());
  expect(response.headers.get("content-type")).toBe(INGRESS_CONTENT_TYPE);
  expect(response.headers.get(KEY_ID_HEADER)).toBe(CURRENT_KEY_ID);
  expect(response.headers.get(SIGNATURE_HEADER)).toBe(
    await responseSignature(body, requestBody, response.status, requestId),
  );
  return decodeCanonicalCbor(body, {
    maxBytes: MAX_BLOB_BYTES + ENVELOPE_HEADROOM_BYTES,
    maxDepth: 72,
    maxItems: 100_000,
  });
}

function expectUnsigned(response: Response): void {
  expect(response.headers.has(KEY_ID_HEADER)).toBe(false);
  expect(response.headers.has(SIGNATURE_HEADER)).toBe(false);
}

describe("authenticated state-app blob ingress", () => {
  it("routes one authenticated blob read, derives all trusted fields, and signs the hydrated bytes", async () => {
    const names: string[] = [];
    let captured: HostRequest | undefined;
    const payload = await ingressPayload();
    const { request, body } = await signedRequest(payload);
    const before = Date.now();
    const response = await invoke(request, environment({
      readSessionBlob: async (unknownRequest) => {
        captured = structuredClone(unknownRequest) as HostRequest;
        return hostSuccess(captured.requestId, await hydratedResult());
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
        digest: await blobDigest(),
      },
    });
    expect(captured!.payload.now).toBeGreaterThanOrEqual(before);
    expect(captured!.payload.now).toBeLessThanOrEqual(after);
    expect(await signedResponse(response, body, identity("req"))).toEqual(
      hostSuccess(identity("req"), await hydratedResult()),
    );
  });

  it("signs a null result when the current state references no such blob", async () => {
    const payload = await ingressPayload();
    const { request, body } = await signedRequest(payload);
    const response = await invoke(request, environment({
      readSessionBlob: async () => hostSuccess(identity("req"), null),
    }));
    expect(response.status).toBe(200);
    expect(await signedResponse(response, body, identity("req"))).toEqual(
      hostSuccess(identity("req"), null),
    );
  });

  it("hydrates a maximum-size blob through the widened response bound", async () => {
    const bytes = new Uint8Array(MAX_BLOB_BYTES).fill(0x5a);
    const payload = { ...(await ingressPayload()), digest: await blobDigest(bytes) };
    const { request, body } = await signedRequest(payload);
    const response = await invoke(request, environment({
      readSessionBlob: async () => hostSuccess(identity("req"), await hydratedResult(bytes)),
    }));
    expect(response.status).toBe(200);
    const decoded = await signedResponse(response, body, identity("req")) as {
      payload: { result: { bytes: Uint8Array; encodedBytes: number } };
    };
    expect(decoded.payload.result.encodedBytes).toBe(MAX_BLOB_BYTES);
    expect(decoded.payload.result.bytes.byteLength).toBe(MAX_BLOB_BYTES);
  });

  it.each([
    ["missing digest", (payload: IngressPayload) => {
      const { digest: _digest, ...rest } = payload;
      return rest;
    }],
    ["extra field", (payload: IngressPayload) => ({ ...payload, afterSequence: 0 })],
    ["read-events field set", (payload: IngressPayload) => {
      const { digest: _digest, ...rest } = payload;
      return { ...rest, afterSequence: 0, limit: 16 };
    }],
    ["malformed digest", (payload: IngressPayload) => ({ ...payload, digest: "sha256:abc" })],
    ["uppercase digest", (payload: IngressPayload) => ({
      ...payload,
      digest: `sha256:${"A".repeat(64)}`,
    })],
    ["zero digest", (payload: IngressPayload) => ({ ...payload, digest: ZERO_DIGEST })],
    ["non-string digest", (payload: IngressPayload) => ({ ...payload, digest: 7 })],
    ["zero generation", (payload: IngressPayload) => ({
      ...payload,
      expectedAuthorizationGeneration: 0,
    })],
    ["wrong protocol", (payload: IngressPayload) => ({
      ...payload,
      protocol: "circulus.state-ingress.v1alpha1",
    })],
    ["wrong schema digest", (payload: IngressPayload) => ({
      ...payload,
      schemaDigest: `sha256:${"6".repeat(64)}`,
    })],
    ["stale clock", (payload: IngressPayload) => ({
      ...payload,
      sentAtUnixMs: Date.now() - 120_000,
    })],
  ])("rejects %s as a signed INVALID_ARGUMENT before routing", async (_name, mutate) => {
    let calls = 0;
    const payload = mutate(await ingressPayload());
    const { request, body } = await signedRequest(payload as IngressPayload);
    const response = await invoke(request, environment({
      readSessionBlob: async () => {
        calls += 1;
        return hostSuccess(identity("req"), null);
      },
    }));
    expect(response.status).toBe(400);
    expect(calls).toBe(0);
    expect(await signedResponse(response, body, identity("req"))).toMatchObject({
      schemaDigest: HOST_SCHEMA_DIGEST,
      requestId: identity("req"),
      payload: { ok: false, error: { code: "INVALID_ARGUMENT" } },
    });
  });

  it.each([
    ["echoes another digest", async () => ({
      ...(await hydratedResult()) as Record<string, NormalizedValue>,
      digest: `sha256:${"1".repeat(64)}`,
    }), "INTERNAL_ERROR"],
    ["declares the wrong length", async () => ({
      ...(await hydratedResult()) as Record<string, NormalizedValue>,
      encodedBytes: BLOB.byteLength + 1,
    }), "INTERNAL_ERROR"],
    ["returns bytes that do not hash to the digest", async () => ({
      digest: await blobDigest(),
      encodedBytes: BLOB.byteLength,
      bytes: new Uint8Array(BLOB.byteLength).fill(0x00),
    }), "INTERNAL_ERROR"],
    ["adds a field", async () => ({
      ...(await hydratedResult()) as Record<string, NormalizedValue>,
      encoding: "cbor",
    }), "INTERNAL_ERROR"],
    ["drops a field", async () => ({
      digest: await blobDigest(),
      bytes: BLOB,
    }), "INTERNAL_ERROR"],
    ["returns empty bytes", async () => ({
      digest: await blobDigest(new Uint8Array(0)),
      encodedBytes: 0,
      bytes: new Uint8Array(0),
    }), "INTERNAL_ERROR"],
    ["returns bytes as text", async () => ({
      digest: await blobDigest(),
      encodedBytes: BLOB.byteLength,
      bytes: "hydrated checkpoint payload bytes",
    }), "INTERNAL_ERROR"],
    ["returns a non-object result", async () => 7, "INTERNAL_ERROR"],
    ["exceeds the blob bound inside the envelope bound", async () => {
      const bytes = new Uint8Array(MAX_BLOB_BYTES + 1).fill(0x5a);
      return hydratedResult(bytes);
    }, "INTERNAL_ERROR"],
    ["exceeds the envelope bound", async () => {
      const bytes = new Uint8Array(MAX_BLOB_BYTES + ENVELOPE_HEADROOM_BYTES).fill(0x5a);
      return hydratedResult(bytes);
    }, "RESOURCE_EXHAUSTED"],
  ])("turns a Host success that %s into a signed 502", async (_name, result, code) => {
    const hostResult = await result();
    const digest = typeof hostResult === "object" && hostResult !== null &&
        !Array.isArray(hostResult) && !(hostResult instanceof Uint8Array) &&
        typeof (hostResult as { digest?: unknown }).digest === "string" &&
        /^sha256:[0-9a-f]{64}$/.test((hostResult as { digest: string }).digest) &&
        (hostResult as { digest: string }).digest !== `sha256:${"1".repeat(64)}`
      ? (hostResult as { digest: Digest }).digest
      : await blobDigest();
    const payload = { ...(await ingressPayload()), digest };
    const { request, body } = await signedRequest(payload);
    const response = await invoke(request, environment({
      readSessionBlob: async () => hostSuccess(identity("req"), hostResult as NormalizedValue),
    }));
    expect(response.status).toBe(502);
    expect(await signedResponse(response, body, identity("req"))).toEqual({
      protocol: HOST_PROTOCOL,
      major: 1,
      minor: 0,
      schemaDigest: HOST_SCHEMA_DIGEST,
      requestId: identity("req"),
      payload: {
        ok: false,
        error: {
          code,
          message: code === "RESOURCE_EXHAUSTED"
            ? "The RPC response exceeds its operation limit."
            : "The operation could not be completed.",
        },
      },
    });
  });

  it("forwards an allowlisted Host failure with its safe message and strips the original text", async () => {
    const payload = await ingressPayload();
    const { request, body } = await signedRequest(payload);
    const response = await invoke(request, environment({
      readSessionBlob: async () => ({
        protocol: HOST_PROTOCOL,
        major: 1,
        minor: 0,
        schemaDigest: HOST_SCHEMA_DIGEST,
        requestId: identity("req"),
        payload: {
          ok: false,
          error: { code: "STALE_GENERATION", message: "internal detail about generation 9" },
        },
      }),
    }));
    expect(response.status).toBe(200);
    expect(await signedResponse(response, body, identity("req"))).toEqual({
      protocol: HOST_PROTOCOL,
      major: 1,
      minor: 0,
      schemaDigest: HOST_SCHEMA_DIGEST,
      requestId: identity("req"),
      payload: {
        ok: false,
        error: { code: "STALE_GENERATION", message: "The supplied generation is stale." },
      },
    });
  });

  it("binds authorization to the exact path, content type, and blob MAC domain", async () => {
    let calls = 0;
    const stub: SessionStub = {
      readSessionBlob: async () => {
        calls += 1;
        return hostSuccess(identity("req"), null);
      },
    };
    const payload = await ingressPayload();
    const body = encodeCanonicalCbor(payload);

    const wrongPath = await requestFromBytes(body, { path: "/circulusd/state/v1/session-blobs:read" });
    const wrongPathResponse = await invoke(wrongPath, environment(stub));
    expect(wrongPathResponse.status).toBe(404);
    expectUnsigned(wrongPathResponse);

    const wrongContentType = await requestFromBytes(body, { contentType: READ_EVENTS_CONTENT_TYPE });
    const wrongContentTypeResponse = await invoke(wrongContentType, environment(stub));
    expect(wrongContentTypeResponse.status).toBe(415);
    expectUnsigned(wrongContentTypeResponse);

    const readEventsDomain = await requestFromBytes(body, {
      signature: await requestSignature(body, { domain: READ_EVENTS_REQUEST_MAC_DOMAIN }),
    });
    const readEventsDomainResponse = await invoke(readEventsDomain, environment(stub));
    expect(readEventsDomainResponse.status).toBe(401);
    expectUnsigned(readEventsDomainResponse);

    const readEventsPath = await requestFromBytes(body, {
      signature: await requestSignature(body, { path: READ_EVENTS_PATH }),
    });
    const readEventsPathResponse = await invoke(readEventsPath, environment(stub));
    expect(readEventsPathResponse.status).toBe(401);
    expectUnsigned(readEventsPathResponse);

    expect(calls).toBe(0);
  });

  it("uses only the read ingress keys and fails closed without them", async () => {
    let calls = 0;
    const payload = await ingressPayload();
    const dispatchKey = new Uint8Array(32).fill(0x51);
    const { request } = await signedRequest(payload, {
      keyId: "dispatch-start-current-1",
      rootKey: dispatchKey,
    });
    const response = await invoke(request, environment({
      readSessionBlob: async () => {
        calls += 1;
        return hostSuccess(identity("req"), null);
      },
    }, [], {
      CIRCULUSD_STATE_DISPATCH_START_CURRENT_KEY_ID: "dispatch-start-current-1",
      CIRCULUSD_STATE_DISPATCH_START_CURRENT_KEY: hex(dispatchKey),
    }));
    expect(response.status).toBe(401);
    expectUnsigned(response);

    const { request: unconfigured } = await signedRequest(payload);
    const unconfiguredResponse = await invoke(unconfigured, environment({
      readSessionBlob: async () => {
        calls += 1;
        return hostSuccess(identity("req"), null);
      },
    }, [], {
      CIRCULUSD_STATE_INGRESS_CURRENT_KEY_ID: undefined,
      CIRCULUSD_STATE_INGRESS_CURRENT_KEY: undefined,
    }));
    expect(unconfiguredResponse.status).toBe(503);
    expectUnsigned(unconfiguredResponse);
    expect(calls).toBe(0);
  });

  it("pins canonical request/response bytes and direction-separated MACs in a shared golden", async () => {
    const fixture = JSON.parse(readFileSync(new URL(
      "../../../packages/protocol-types/fixtures/state-app-blob-ingress-v1alpha1.json",
      import.meta.url,
    ), "utf8"));
    expect(fixture.protocol).toBe(INGRESS_PROTOCOL);
    expect(fixture.schemaDigest).toBe(INGRESS_SCHEMA_DIGEST);
    expect(fixture.path).toBe(INGRESS_PATH);
    expect(fixture.contentType).toBe(INGRESS_CONTENT_TYPE);
    expect(fixture.response.schemaDigest).toBe(HOST_SCHEMA_DIGEST);

    const blob = decodeHex(fixture.blobHex);
    expect(await blobDigest(blob)).toBe(fixture.request.digest);
    expect(fixture.response.payload.result).toEqual({
      digest: fixture.request.digest,
      encodedBytes: blob.byteLength,
    });
    const rootKey = decodeHex(fixture.rootKeyHex);
    const requestBody = encodeCanonicalCbor(fixture.request);
    const responseBody = encodeCanonicalCbor({
      ...fixture.response,
      payload: {
        ok: true,
        result: { ...fixture.response.payload.result, bytes: blob },
      },
    });
    expect(hex(requestBody)).toBe(fixture.requestCborHex);
    expect(await requestSignature(requestBody, { keyId: fixture.keyId, rootKey })).toBe(
      fixture.requestMacHex,
    );
    expect(hex(responseBody)).toBe(fixture.responseCborHex);
    expect(await responseSignature(
      responseBody,
      requestBody,
      fixture.responseStatus,
      fixture.request.requestId,
      fixture.keyId,
      rootKey,
    )).toBe(fixture.responseMacHex);
    expect(fixture.responseMacHex).not.toBe(fixture.requestMacHex);
  });
});
