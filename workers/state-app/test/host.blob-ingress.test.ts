import { readFileSync } from "node:fs";

import { describe, expect, it, vi } from "vitest";

import {
  decodeCanonicalCbor,
  digestBytes,
  encodeCanonicalCbor,
  type NormalizedValue,
} from "@circulusd/protocol-types";

import worker from "../src/host/worker.ts";
import { HOST_RPC_CONTRACTS } from "../src/host/rpc.ts";

const PATH = "/circulusd/state/v1/session-blob:read";
const CONTENT_TYPE = "application/vnd.circulusd.state-blob-ingress+cbor";
const PROTOCOL = "circulus.state-blob-ingress.v1alpha1";
const SCHEMA_DIGEST =
  "sha256:d9402c455a2d37e51885684aa26ade9d26ff444cc5a15fb89c2ce2af372e40e5";
const KEY_ID = "state-current-1";
const ROOT_KEY = new Uint8Array(32).fill(0x31);
const MAX_BLOB_BYTES = 4 * 1_048_576;
const MAX_RESPONSE_BYTES = MAX_BLOB_BYTES + 65_536;
const HOST_CONTRACT = HOST_RPC_CONTRACTS["session.read-blob"];
const text = (value: string) => new TextEncoder().encode(value);
const hex = (value: Uint8Array) =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");
const identity = (kind: string) => `${kind}_${"A".repeat(26)}`;
const fromHex = (value: string) => new Uint8Array(Buffer.from(value, "hex"));

function framed(parts: readonly Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((size, part) => size + 4 + part.length, 0));
  const view = new DataView(result.buffer);
  let offset = 0;
  for (const part of parts) {
    view.setUint32(offset, part.length, false);
    offset += 4;
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

async function hmac(key: Uint8Array, bytes: Uint8Array): Promise<Uint8Array> {
  const imported = await crypto.subtle.importKey(
    "raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", imported, bytes));
}

async function directionalKey(root: Uint8Array, direction: "request" | "response") {
  return hmac(root, text(`circulusd.state-ingress.key.${direction}.v1\0`));
}

async function blob(bytes = text("checkpoint payload")) {
  return { digest: await digestBytes(bytes), encodedBytes: bytes.length, bytes };
}

function requestPayload(digest: string) {
  return {
    protocol: PROTOCOL,
    major: 1,
    minor: 0,
    schemaDigest: SCHEMA_DIGEST,
    requestId: identity("req"),
    sentAtUnixMs: Date.now(),
    tenantId: identity("tenant"),
    actorSubjectId: identity("subject"),
    sessionId: identity("sess"),
    expectedAuthorizationGeneration: 7,
    digest,
  };
}

function hostResponse(requestId: string, result: unknown) {
  return {
    protocol: "circulus.v1alpha1",
    major: 1,
    minor: 0,
    schemaDigest: HOST_CONTRACT.schemaDigest,
    requestId,
    payload: { ok: true, result },
  };
}

async function signedRequest(
  payload: unknown,
  options: {
    domain?: string;
    signedPath?: string;
    path?: string;
    keyId?: string;
    rootKey?: Uint8Array;
    signature?: string;
    body?: Uint8Array;
    headers?: Record<string, string>;
  } = {},
) {
  const body = options.body ?? encodeCanonicalCbor(payload);
  const keyId = options.keyId ?? KEY_ID;
  const signature = options.signature ?? hex(await hmac(
    await directionalKey(options.rootKey ?? ROOT_KEY, "request"),
    framed([
      text(options.domain ?? "circulusd.state-blob-ingress.request.v1"),
      text(keyId), text("POST"), text(options.signedPath ?? PATH), await sha256(body),
    ]),
  ));
  return {
    body,
    request: new Request(`http://127.0.0.1:8787${options.path ?? PATH}`, {
      method: "POST",
      headers: {
        "content-type": CONTENT_TYPE,
        "x-circulus-state-key-id": keyId,
        "x-circulus-state-signature": signature,
        ...options.headers,
      },
      body,
    }),
  };
}

function environment(readSessionBlob: (request: unknown) => Promise<unknown>) {
  const getByName = vi.fn(() => ({ readSessionBlob }));
  return {
    CIRCULUSD_STATE_INGRESS_CURRENT_KEY_ID: KEY_ID,
    CIRCULUSD_STATE_INGRESS_CURRENT_KEY: hex(ROOT_KEY),
    SESSION_CELL: { getByName },
  };
}

async function readSignedResponse(
  response: Response,
  requestBody: Uint8Array,
  requestId = identity("req"),
  keyId = KEY_ID,
  rootKey = ROOT_KEY,
): Promise<NormalizedValue> {
  const body = new Uint8Array(await response.arrayBuffer());
  expect(response.headers.get("content-type")).toBe(CONTENT_TYPE);
  expect(response.headers.get("cache-control")).toBe("no-store");
  expect(response.headers.get("x-circulus-state-key-id")).toBe(keyId);
  expect(response.headers.get("x-circulus-state-signature")).toBe(hex(await hmac(
    await directionalKey(rootKey, "response"),
    framed([
      text("circulusd.state-blob-ingress.response.v1"), text(keyId), text(requestId),
      await sha256(requestBody), text(String(response.status)), text(CONTENT_TYPE),
      await sha256(body),
    ]),
  )));
  return decodeCanonicalCbor(body, { maxBytes: MAX_RESPONSE_BYTES });
}

function expectUnsigned(response: Response): void {
  expect(response.headers.has("x-circulus-state-key-id")).toBe(false);
  expect(response.headers.has("x-circulus-state-signature")).toBe(false);
}

describe("authenticated session blob ingress", () => {
  it("pins the request schema to its documented descriptor", async () => {
    const descriptor = "circulus.state-blob-ingress.v1alpha1|major=1|minor=0|requestId:req|sentAtUnixMs:safe-uint|" +
      "tenantId:tenant|actorSubjectId:subject|sessionId:sess|expectedAuthorizationGeneration:positive-safe-uint|" +
      "digest:sha256|fields=protocol,major,minor,schemaDigest,requestId,sentAtUnixMs,tenantId,actorSubjectId,sessionId," +
      "expectedAuthorizationGeneration,digest|maxBytes=4096|maxDepth=2|maxItems=32";
    expect(await digestBytes(text(descriptor))).toBe(SCHEMA_DIGEST);
  });

  it("matches the shared Go/TypeScript request and response golden", async () => {
    const fixture = JSON.parse(readFileSync(new URL(
      "../../../packages/protocol-types/fixtures/state-app-blob-ingress-v1alpha1.json",
      import.meta.url,
    ), "utf8")) as {
      request: ReturnType<typeof requestPayload>;
      keyId: string;
      rootKeyHex: string;
      requestCborHex: string;
      requestMacHex: string;
      responseStatus: number;
      response: {
        payload: { result: { digest: string; encodedBytes: number; bytes: { hex: string } } };
      };
      responseCborHex: string;
      responseMacHex: string;
    };
    const rootKey = fromHex(fixture.rootKeyHex);
    const result = fixture.response.payload.result;
    expect(fixture).toMatchObject({
      protocol: PROTOCOL,
      schemaDigest: SCHEMA_DIGEST,
      path: PATH,
      contentType: CONTENT_TYPE,
      response: { schemaDigest: HOST_CONTRACT.schemaDigest },
    });
    expect(await digestBytes(fromHex(result.bytes.hex))).toBe(result.digest);
    expect(result.digest).toBe(fixture.request.digest);
    expect(result.encodedBytes).toBe(fromHex(result.bytes.hex).byteLength);
    const expectedResponse = {
      ...fixture.response,
      payload: { ok: true, result: { ...result, bytes: fromHex(result.bytes.hex) } },
    };
    const clock = vi.spyOn(Date, "now").mockReturnValue(fixture.request.sentAtUnixMs);
    try {
      const { request, body } = await signedRequest(fixture.request, {
        keyId: fixture.keyId, rootKey,
      });
      expect(hex(body)).toBe(fixture.requestCborHex);
      expect(request.headers.get("x-circulus-state-signature")).toBe(fixture.requestMacHex);
      const env = {
        ...environment(async () => expectedResponse),
        CIRCULUSD_STATE_INGRESS_CURRENT_KEY_ID: fixture.keyId,
        CIRCULUSD_STATE_INGRESS_CURRENT_KEY: fixture.rootKeyHex,
      };
      const response = await worker.fetch(request, env as never);
      expect(response.status).toBe(fixture.responseStatus);
      expect(response.headers.get("x-circulus-state-signature")).toBe(fixture.responseMacHex);
      expect(hex(new Uint8Array(await response.clone().arrayBuffer()))).toBe(fixture.responseCborHex);
      expect(await readSignedResponse(
        response, body, fixture.request.requestId, fixture.keyId, rootKey,
      )).toEqual(expectedResponse);
      expect(fixture.responseMacHex).not.toBe(fixture.requestMacHex);
    } finally {
      clock.mockRestore();
    }
  });

  it("routes a blob read with scoped authority and host-observed time", async () => {
    const value = await blob();
    const payload = requestPayload(value.digest);
    const call = vi.fn(async (request: unknown) => {
      const envelope = request as { requestId: string };
      return hostResponse(envelope.requestId, value);
    });
    const env = environment(call);
    const { request, body } = await signedRequest(payload);
    const before = Date.now();
    const response = await worker.fetch(request, env as never);
    const after = Date.now();
    expect(response.status).toBe(200);
    expect(env.SESSION_CELL.getByName).toHaveBeenCalledExactlyOnceWith(JSON.stringify([
      "circulusd.state-app.cell", 1, "session", payload.tenantId, payload.sessionId,
    ]));
    const captured = call.mock.calls[0]![0] as { payload: { now: number } };
    expect(captured.payload.now).toBeGreaterThanOrEqual(before);
    expect(captured.payload.now).toBeLessThanOrEqual(after);
    expect(captured).toEqual({
      protocol: "circulus.v1alpha1", major: 1, minor: 0,
      schemaDigest: HOST_CONTRACT.schemaDigest, requestId: payload.requestId,
      payload: {
        authority: {
          serviceBinding: "state", tenantId: payload.tenantId,
          actorUserId: payload.actorSubjectId, subjectKind: "session", subjectId: payload.sessionId,
          roles: [], permissions: ["session.read"], authorizationGeneration: 7,
          currentAuthorizationGeneration: 7, issuedAt: captured.payload.now,
          expiresAt: captured.payload.now + 1,
        },
        now: captured.payload.now, digest: value.digest,
      },
    });
    expect(await readSignedResponse(response, body)).toEqual(hostResponse(payload.requestId, value));
  });

  it("preserves a missing referenced blob as authenticated null", async () => {
    const payload = requestPayload((await blob()).digest);
    const { request, body } = await signedRequest(payload);
    const response = await worker.fetch(request, environment(async () =>
      hostResponse(payload.requestId, null)
    ) as never);
    expect(response.status).toBe(200);
    expect(await readSignedResponse(response, body)).toEqual(hostResponse(payload.requestId, null));
  });

  it.each([
    ["events MAC domain", { domain: "circulusd.state-ingress.request.v1" }],
    ["events path", { signedPath: "/circulusd/state/v1/session-events:read" }],
    ["invalid signature", { signature: "0".repeat(64) }],
    ["unconfigured key", { keyId: "not-configured" }],
  ])("rejects %s before any cell lookup", async (_name, options) => {
    const payload = requestPayload((await blob()).digest);
    const { request } = await signedRequest(payload, options);
    const env = environment(async () => { throw new Error("must not call"); });
    const response = await worker.fetch(request, env as never);
    expect(response.status).toBe(401);
    expectUnsigned(response);
    expect(env.SESSION_CELL.getByName).not.toHaveBeenCalled();
  });

  it.each([
    ["malformed digest", { digest: "sha256:nope" }],
    ["uppercase digest", { digest: `sha256:${"A".repeat(64)}` }],
    ["zero digest", { digest: `sha256:${"0".repeat(64)}` }],
    ["non-string digest", { digest: 7 }],
    ["foreign protocol", { protocol: "circulus.state-ingress.v1alpha1" }],
    ["foreign schema", { schemaDigest: `sha256:${"0".repeat(64)}` }],
    ["expired timestamp", { sentAtUnixMs: 1 }],
    ["invalid tenant", { tenantId: "tenant-1" }],
    ["invalid actor", { actorSubjectId: "subject-1" }],
    ["invalid session", { sessionId: "session-1" }],
    ["zero generation", { expectedAuthorizationGeneration: 0 }],
    ["extra authority", { authority: {} }],
    ["extra pagination", { limit: 1 }],
    ["read-events field set", { afterSequence: 0, limit: 16 }],
  ])("rejects authenticated %s before any cell lookup", async (_name, patch) => {
    const payload = { ...requestPayload((await blob()).digest), ...patch };
    const { request, body } = await signedRequest(payload);
    const env = environment(async () => { throw new Error("must not call"); });
    const response = await worker.fetch(request, env as never);
    expect(response.status).toBe(400);
    expect(env.SESSION_CELL.getByName).not.toHaveBeenCalled();
    expect(await readSignedResponse(response, body)).toMatchObject({
      payload: { ok: false, error: { code: "INVALID_ARGUMENT" } },
    });
  });

  it("rejects a missing digest before any cell lookup", async () => {
    const { digest: _digest, ...payload } = requestPayload((await blob()).digest);
    const { request, body } = await signedRequest(payload);
    const env = environment(async () => { throw new Error("must not call"); });
    const response = await worker.fetch(request, env as never);
    expect(response.status).toBe(400);
    expect(env.SESSION_CELL.getByName).not.toHaveBeenCalled();
    expect(await readSignedResponse(response, body)).toMatchObject({
      payload: { ok: false, error: { code: "INVALID_ARGUMENT" } },
    });
  });

  it.each([
    ["unknown blob URL", { path: "/circulusd/state/v1/session-blobs:read" }, 404],
    ["events content type", {
      headers: { "content-type": "application/vnd.circulusd.state-ingress+cbor" },
    }, 415],
  ])("rejects %s before any cell lookup", async (_name, options, status) => {
    const { request } = await signedRequest(requestPayload((await blob()).digest), options);
    const env = environment(async () => { throw new Error("must not call"); });
    const response = await worker.fetch(request, env as never);
    expect(response.status).toBe(status);
    expectUnsigned(response);
    expect(env.SESSION_CELL.getByName).not.toHaveBeenCalled();
  });

  it("rejects a configured dispatch key for blob reads", async () => {
    const keyId = "dispatch-start-current-1";
    const rootKey = new Uint8Array(32).fill(0x51);
    const { request } = await signedRequest(requestPayload((await blob()).digest), { keyId, rootKey });
    const env = {
      ...environment(async () => { throw new Error("must not call"); }),
      CIRCULUSD_STATE_DISPATCH_START_CURRENT_KEY_ID: keyId,
      CIRCULUSD_STATE_DISPATCH_START_CURRENT_KEY: hex(rootKey),
    };
    const response = await worker.fetch(request, env as never);
    expect(response.status).toBe(401);
    expectUnsigned(response);
    expect(env.SESSION_CELL.getByName).not.toHaveBeenCalled();
  });

  it("fails closed when the read credentials are absent", async () => {
    const { request } = await signedRequest(requestPayload((await blob()).digest));
    const env = {
      ...environment(async () => { throw new Error("must not call"); }),
      CIRCULUSD_STATE_INGRESS_CURRENT_KEY_ID: undefined,
      CIRCULUSD_STATE_INGRESS_CURRENT_KEY: undefined,
    };
    const response = await worker.fetch(request, env as never);
    expect(response.status).toBe(503);
    expectUnsigned(response);
    expect(env.SESSION_CELL.getByName).not.toHaveBeenCalled();
  });

  it("accepts the previous read key during rotation", async () => {
    const value = await blob();
    const payload = requestPayload(value.digest);
    const keyId = "state-previous-1";
    const rootKey = new Uint8Array(48).fill(0x42);
    const { request, body } = await signedRequest(payload, { keyId, rootKey });
    const env = {
      ...environment(async () => hostResponse(payload.requestId, value)),
      CIRCULUSD_STATE_INGRESS_PREVIOUS_KEY_ID: keyId,
      CIRCULUSD_STATE_INGRESS_PREVIOUS_KEY: hex(rootKey),
    };
    const response = await worker.fetch(request, env as never);
    expect(response.status).toBe(200);
    expect(await readSignedResponse(response, body, payload.requestId, keyId, rootKey)).toEqual(
      hostResponse(payload.requestId, value),
    );
  });

  it.each(["STALE_GENERATION", "PERMISSION_DENIED", "CORRUPT_STATE"])(
    "authenticates and sanitizes host %s errors", async (code) => {
      const payload = requestPayload((await blob()).digest);
      const { request, body } = await signedRequest(payload);
      const response = await worker.fetch(request, environment(async () => ({
        ...hostResponse(payload.requestId, null),
        payload: { ok: false, error: { code, message: "private host details" } },
      })) as never);
      expect(response.status).toBe(200);
      const result = await readSignedResponse(response, body);
      expect(result).toMatchObject({ payload: { ok: false, error: { code } } });
      expect(JSON.stringify(result)).not.toContain("private host details");
      if (code === "STALE_GENERATION") {
        expect(result).toEqual({
          protocol: "circulus.v1alpha1", major: 1, minor: 0,
          schemaDigest: HOST_CONTRACT.schemaDigest, requestId: payload.requestId,
          payload: {
            ok: false,
            error: { code, message: "The supplied generation is stale." },
          },
        });
      }
    },
  );

  it.each([
    "wrong digest", "corrupt bytes", "wrong length", "missing bytes", "extra field", "empty blob", "bytes as text",
  ])("rejects a host success containing %s", async (kind) => {
    const value = await blob();
    const invalid: Record<string, unknown> = { ...value };
    if (kind === "wrong digest") invalid.digest = `sha256:${"0".repeat(64)}`;
    if (kind === "corrupt bytes") invalid.bytes = new Uint8Array(value.bytes.length).fill(3);
    if (kind === "wrong length") invalid.encodedBytes = value.encodedBytes + 1;
    if (kind === "missing bytes") delete invalid.bytes;
    if (kind === "extra field") invalid.privateData = "must not forward";
    if (kind === "empty blob") Object.assign(invalid, await blob(new Uint8Array()));
    if (kind === "bytes as text") invalid.bytes = "hydrated checkpoint payload bytes";
    const payload = requestPayload(kind === "empty blob" ? invalid.digest as string : value.digest);
    const { request, body } = await signedRequest(payload);
    const response = await worker.fetch(request, environment(async () =>
      hostResponse(payload.requestId, invalid)
    ) as never);
    expect(response.status).toBe(502);
    expect(await readSignedResponse(response, body)).toMatchObject({
      payload: { ok: false, error: { code: "INTERNAL_ERROR" } },
    });
  });

  it("rejects a non-object host result", async () => {
    const payload = requestPayload((await blob()).digest);
    const { request, body } = await signedRequest(payload);
    const response = await worker.fetch(request, environment(async () =>
      hostResponse(payload.requestId, 7)
    ) as never);
    expect(response.status).toBe(502);
    expect(await readSignedResponse(response, body)).toMatchObject({
      payload: { ok: false, error: { code: "INTERNAL_ERROR" } },
    });
  });

  it("reports a host response beyond the envelope bound as RESOURCE_EXHAUSTED", async () => {
    const value = await blob(new Uint8Array(MAX_RESPONSE_BYTES).fill(0x5a));
    const payload = requestPayload(value.digest);
    const { request, body } = await signedRequest(payload);
    const response = await worker.fetch(request, environment(async () =>
      hostResponse(payload.requestId, value)
    ) as never);
    expect(response.status).toBe(502);
    expect(await readSignedResponse(response, body)).toEqual({
      protocol: "circulus.v1alpha1", major: 1, minor: 0,
      schemaDigest: HOST_CONTRACT.schemaDigest, requestId: payload.requestId,
      payload: {
        ok: false,
        error: { code: "RESOURCE_EXHAUSTED", message: "The RPC response exceeds its operation limit." },
      },
    });
  });

  it("accepts exactly 4 MiB without increasing other operation limits", async () => {
    const value = await blob(new Uint8Array(MAX_BLOB_BYTES).fill(19));
    const payload = requestPayload(value.digest);
    const { request, body } = await signedRequest(payload);
    const response = await worker.fetch(request, environment(async () =>
      hostResponse(payload.requestId, value)
    ) as never);
    expect(response.status).toBe(200);
    const decoded = await readSignedResponse(response, body) as {
      payload: { result: Awaited<ReturnType<typeof blob>> };
    };
    expect(decoded.payload.result.encodedBytes).toBe(MAX_BLOB_BYTES);
    expect(decoded.payload.result.bytes.length).toBe(MAX_BLOB_BYTES);
    expect(await digestBytes(decoded.payload.result.bytes)).toBe(value.digest);
    expect(HOST_RPC_CONTRACTS["session.read-events"].responseMaxEncodedBytes).toBe(1_048_576 + 65_536);
  });

  it("rejects a blob beyond 4 MiB even when the response envelope fits", async () => {
    const value = await blob(new Uint8Array(MAX_BLOB_BYTES + 1));
    const payload = requestPayload(value.digest);
    const { request, body } = await signedRequest(payload);
    const response = await worker.fetch(request, environment(async () =>
      hostResponse(payload.requestId, value)
    ) as never);
    expect(response.status).toBe(502);
    expect(await readSignedResponse(response, body)).toMatchObject({
      payload: { ok: false, error: { code: "INTERNAL_ERROR" } },
    });
  });
});
