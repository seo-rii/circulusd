import { describe, expect, it } from "vitest";

import {
  decodeCanonicalCbor,
  digestBytes,
  encodeCanonicalCbor,
  type AgentCheckpoint,
  type Digest,
  type NormalizedValue,
} from "@circulusd/protocol-types";

import type { AggregateAdapter } from "../src/host/contracts.ts";
import { TransactionalAggregateKernel } from "../src/host/kernel.ts";
import worker from "../src/host/worker.ts";
import {
  applySessionCommand,
  checkpointDigest,
  createSessionState,
  effectRequestDigest,
  migrateSessionState,
  turnInputDigest,
  validateSessionState,
  type CreateSessionStateInput,
  type SessionAggregateState,
  type SessionCommand,
  type SessionCommandOutcome,
} from "../src/session/index.ts";
import { RestartableDurableStorage } from "./support/restartable-durable-storage.ts";

const INGRESS_PATH = "/circulusd/state/v1/session-dispatch-start:claim";
const INGRESS_CONTENT_TYPE =
  "application/vnd.circulusd.state-dispatch-start-ingress+cbor";
const INGRESS_PROTOCOL = "circulus.state-dispatch-start-ingress.v1alpha1";
const INGRESS_SCHEMA_DIGEST =
  "sha256:a86295cc9ad723e50c8729318e4ec4994faa7b4c64c30a718696de8fa6edc724";
const HOST_PROTOCOL = "circulus.v1alpha1";
const HOST_SCHEMA_DIGEST =
  "sha256:91ae9bd8a93e99916a3e1e1e200d5cdf90bdc693bb0b3791066e1e1d5a559db5";
const CLAIM_KEY_ID = "dispatch-start-current-1";
const CLAIM_KEY = new Uint8Array(32).fill(0x51);
const READ_KEY_ID = "state-current-1";
const READ_KEY = new Uint8Array(32).fill(0x31);
const KEY_ID_HEADER = "x-circulus-state-key-id";
const SIGNATURE_HEADER = "x-circulus-state-signature";
const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const CANONICAL_BASE32_FINAL = "AEIMQUY4";
const ROUTE_DIGEST = `sha256:${"7".repeat(64)}`;
const REQUEST_DIGEST = `sha256:${"6".repeat(64)}`;
const COMMAND_DIGEST = `sha256:${"8".repeat(64)}`;

const sessionAdapter: AggregateAdapter<
  SessionAggregateState,
  CreateSessionStateInput,
  SessionCommand,
  SessionCommandOutcome
> = {
  kind: "dispatch-start-ingress-session",
  create: createSessionState,
  migrate: migrateSessionState,
  validate: validateSessionState,
  apply: applySessionCommand,
  version: (state) => state.eventSequence,
};

interface SessionStub {
  readSessionEvents?(request: unknown): Promise<unknown>;
  executeSessionCommand?(request: unknown): Promise<unknown>;
}

interface TestEnvironment {
  readonly CIRCULUSD_STATE_INGRESS_CURRENT_KEY_ID?: string;
  readonly CIRCULUSD_STATE_INGRESS_CURRENT_KEY?: string;
  readonly CIRCULUSD_STATE_DISPATCH_START_CURRENT_KEY_ID?: string;
  readonly CIRCULUSD_STATE_DISPATCH_START_CURRENT_KEY?: string;
  readonly SESSION_CELL: {
    getByName(name: string): SessionStub;
  };
}

type ClaimPayload = ReturnType<typeof claimPayload>;

function identity(
  kind:
    | "req"
    | "tenant"
    | "subject"
    | "sess"
    | "turn"
    | "effect"
    | "inv"
    | "ws",
  index = 0,
): string {
  const high = BASE32[Math.floor(index / CANONICAL_BASE32_FINAL.length)] ?? "A";
  const low = CANONICAL_BASE32_FINAL[index % CANONICAL_BASE32_FINAL.length] ?? "A";
  return `${kind}_${"A".repeat(24)}${high}${low}`;
}

function dispatchPermitClaims() {
  return {
    tenantId: identity("tenant"),
    userId: identity("subject"),
    sessionId: identity("sess"),
    turnId: identity("turn"),
    effectId: identity("effect"),
    invocationId: identity("inv"),
    requestDigest: REQUEST_DIGEST,
    service: "executor",
    operation: "process.spawn",
    replayPolicy: "idempotency-key",
    dispatchAttempt: 3,
    turnLeaseGeneration: 4,
    placementGeneration: 5,
    sandboxGeneration: 6,
    authorizationGeneration: 7,
    providerRouteDigest: ROUTE_DIGEST,
    deadline: 1_900_000_060_000,
  };
}

function claimPayload(index = 0, sentAtUnixMs = Date.now()) {
  return {
    protocol: INGRESS_PROTOCOL,
    major: 1,
    minor: 0,
    schemaDigest: INGRESS_SCHEMA_DIGEST,
    requestId: identity("req", index),
    sentAtUnixMs,
    tenantId: identity("tenant"),
    workspaceId: identity("ws"),
    sessionId: identity("sess"),
    commandId: "claim-dispatch-start-1",
    expectedEventSequence: 12,
    turnId: identity("turn"),
    effectId: identity("effect"),
    invocationId: identity("inv"),
    requestDigest: REQUEST_DIGEST,
    fence: {
      turnLeaseGeneration: 4,
      placementGeneration: 5,
      sandboxGeneration: 6,
      authorizationGeneration: 7,
    },
    dispatchAttempt: 3,
    providerRequestId: identity("req", 70),
    providerRouteDigest: ROUTE_DIGEST,
    dispatchPermitClaims: dispatchPermitClaims(),
    commandDigest: COMMAND_DIGEST,
  };
}

function text(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function hex(value: Uint8Array): string {
  return [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");
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
  path = INGRESS_PATH,
  keyId = CLAIM_KEY_ID,
  rootKey = CLAIM_KEY,
): Promise<string> {
  const key = await directionalKey(rootKey, "request");
  return hex(await hmac(key, lengthPrefixed([
    text("circulusd.state-dispatch-start-ingress.request.v1"),
    text(keyId),
    text("POST"),
    text(path),
    await sha256(body),
  ])));
}

async function responseSignature(
  body: Uint8Array,
  requestBody: Uint8Array,
  status: number,
  requestId: string,
  keyId = CLAIM_KEY_ID,
  rootKey = CLAIM_KEY,
): Promise<string> {
  const key = await directionalKey(rootKey, "response");
  return hex(await hmac(key, lengthPrefixed([
    text("circulusd.state-dispatch-start-ingress.response.v1"),
    text(keyId),
    text(requestId),
    await sha256(requestBody),
    text(String(status)),
    text(INGRESS_CONTENT_TYPE),
    await sha256(body),
  ])));
}

async function requestFromPayload(
  payload: ClaimPayload | Record<string, unknown>,
  options: {
    readonly path?: string;
    readonly signaturePath?: string;
    readonly signature?: string;
    readonly keyId?: string;
    readonly rootKey?: Uint8Array;
  } = {},
): Promise<{ readonly request: Request; readonly body: Uint8Array }> {
  const body = encodeCanonicalCbor(payload);
  const path = options.path ?? INGRESS_PATH;
  const keyId = options.keyId ?? CLAIM_KEY_ID;
  const rootKey = options.rootKey ?? CLAIM_KEY;
  const headers = new Headers({
    "content-type": INGRESS_CONTENT_TYPE,
    [KEY_ID_HEADER]: keyId,
    [SIGNATURE_HEADER]: options.signature ??
      await requestSignature(body, options.signaturePath ?? path, keyId, rootKey),
  });
  return {
    request: new Request(`http://127.0.0.1:8787${path}`, {
      method: "POST",
      headers,
      body,
    }),
    body,
  };
}

function hostSuccess(
  requestId: string,
  command: Record<string, unknown>,
  fresh: boolean,
  sequence: {
    readonly claimedEventSequence?: number;
    readonly version?: number;
  } = {},
) {
  const dispatch = command.dispatchPermitClaims as Record<string, unknown>;
  const claimedEventSequence = sequence.claimedEventSequence ?? 13;
  const version = sequence.version ?? (fresh ? claimedEventSequence : 20);
  return {
    protocol: HOST_PROTOCOL,
    major: 1,
    minor: 0,
    schemaDigest: HOST_SCHEMA_DIGEST,
    requestId,
    payload: {
      ok: true,
      result: {
        outcome: {
          kind: "dispatch_start_claimed",
          effectId: command.effectId,
          fresh,
          startPermit: {
            dispatchPermitClaims: dispatch,
            providerRequestId: command.providerRequestId,
            commandDigest: command.commandDigest,
            claimedEventSequence,
          },
        },
        version,
        replayed: !fresh,
      },
    },
  };
}

function environment(stub: SessionStub, names: string[] = []): TestEnvironment {
  return {
    CIRCULUSD_STATE_DISPATCH_START_CURRENT_KEY_ID: CLAIM_KEY_ID,
    CIRCULUSD_STATE_DISPATCH_START_CURRENT_KEY: hex(CLAIM_KEY),
    SESSION_CELL: {
      getByName: (name) => {
        names.push(name);
        return stub;
      },
    },
  };
}

async function invoke(request: Request, env: TestEnvironment): Promise<Response> {
  return worker.fetch(request, env as never);
}

async function decodedSignedResponse(
  response: Response,
  requestBody: Uint8Array,
  requestId: string,
): Promise<NormalizedValue> {
  const body = new Uint8Array(await response.arrayBuffer());
  expect(response.headers.get("content-type")).toBe(INGRESS_CONTENT_TYPE);
  expect(response.headers.get(KEY_ID_HEADER)).toBe(CLAIM_KEY_ID);
  expect(response.headers.get(SIGNATURE_HEADER)).toBe(
    await responseSignature(body, requestBody, response.status, requestId),
  );
  return decodeCanonicalCbor(body);
}

function expectUnsigned(response: Response): void {
  expect(response.headers.has(KEY_ID_HEADER)).toBe(false);
  expect(response.headers.has(SIGNATURE_HEADER)).toBe(false);
}

describe("authenticated dispatch-start claim ingress", () => {
  it("uses only dispatch-start credentials and fails closed without them", async () => {
    const payload = claimPayload();
    let calls = 0;
    const stub: SessionStub = {
      executeSessionCommand: async (unknownRequest) => {
        calls += 1;
        const envelope = unknownRequest as {
          requestId: string;
          payload: Record<string, unknown>;
        };
        return hostSuccess(envelope.requestId, envelope.payload, true);
      },
    };

    const readSigned = await requestFromPayload(payload, {
      keyId: READ_KEY_ID,
      rootKey: READ_KEY,
    });
    const bothCredentials: TestEnvironment = {
      CIRCULUSD_STATE_INGRESS_CURRENT_KEY_ID: READ_KEY_ID,
      CIRCULUSD_STATE_INGRESS_CURRENT_KEY: hex(READ_KEY),
      CIRCULUSD_STATE_DISPATCH_START_CURRENT_KEY_ID: CLAIM_KEY_ID,
      CIRCULUSD_STATE_DISPATCH_START_CURRENT_KEY: hex(CLAIM_KEY),
      SESSION_CELL: { getByName: () => stub },
    };
    const readKeyResponse = await invoke(readSigned.request, bothCredentials);
    expect(readKeyResponse.status).toBe(401);
    expectUnsigned(readKeyResponse);
    expect(calls).toBe(0);

    const missingClaimConfig = await requestFromPayload(payload, {
      keyId: READ_KEY_ID,
      rootKey: READ_KEY,
    });
    const missingClaimResponse = await invoke(missingClaimConfig.request, {
      CIRCULUSD_STATE_INGRESS_CURRENT_KEY_ID: READ_KEY_ID,
      CIRCULUSD_STATE_INGRESS_CURRENT_KEY: hex(READ_KEY),
      SESSION_CELL: { getByName: () => stub },
    });
    expect(missingClaimResponse.status).toBe(503);
    expectUnsigned(missingClaimResponse);
    expect(calls).toBe(0);

    const claimSigned = await requestFromPayload(payload);
    const claimResponse = await invoke(claimSigned.request, environment(stub));
    expect(claimResponse.status).toBe(200);
    expect(await decodedSignedResponse(
      claimResponse,
      claimSigned.body,
      payload.requestId,
    )).toEqual(hostSuccess(payload.requestId, {
      kind: "claim_dispatch_start",
      commandId: payload.commandId,
      expectedEventSequence: payload.expectedEventSequence,
      workspaceId: payload.workspaceId,
      turnId: payload.turnId,
      effectId: payload.effectId,
      invocationId: payload.invocationId,
      requestDigest: payload.requestDigest,
      fence: payload.fence,
      transactionTime: 0,
      dispatchAttempt: payload.dispatchAttempt,
      providerRequestId: payload.providerRequestId,
      providerRouteDigest: payload.providerRouteDigest,
      dispatchPermitClaims: payload.dispatchPermitClaims,
      commandDigest: payload.commandDigest,
    }, true));
    expect(calls).toBe(1);
  });

  it("constructs only claim_dispatch_start with a host-owned stable transactionTime", async () => {
    const names: string[] = [];
    let captured: Record<string, unknown> | undefined;
    const payload = claimPayload(0, 1_900_000_000_000);
    const { request, body } = await requestFromPayload(payload);
    const dateNow = Date.now;
    Date.now = () => 1_900_000_000_000;
    try {
      const response = await invoke(request, environment({
        executeSessionCommand: async (unknownRequest) => {
          const envelope = structuredClone(unknownRequest) as {
            requestId: string;
            payload: Record<string, unknown>;
          };
          captured = envelope.payload;
          return hostSuccess(envelope.requestId, envelope.payload, true);
        },
      }, names));

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
        kind: "claim_dispatch_start",
        commandId: payload.commandId,
        expectedEventSequence: payload.expectedEventSequence,
        workspaceId: payload.workspaceId,
        turnId: payload.turnId,
        effectId: payload.effectId,
        invocationId: payload.invocationId,
        requestDigest: payload.requestDigest,
        fence: payload.fence,
        transactionTime: 0,
        dispatchAttempt: payload.dispatchAttempt,
        providerRequestId: payload.providerRequestId,
        providerRouteDigest: payload.providerRouteDigest,
        dispatchPermitClaims: payload.dispatchPermitClaims,
        commandDigest: payload.commandDigest,
      });
      expect(await decodedSignedResponse(response, body, payload.requestId)).toEqual(
        hostSuccess(payload.requestId, captured!, true),
      );
    } finally {
      Date.now = dateNow;
    }
  });

  it("allows exactly one fresh result across 64 concurrent claims and replays nonfresh", async () => {
    const storage = new RestartableDurableStorage();
    const durableKernel = new TransactionalAggregateKernel(
      { storage },
      sessionAdapter,
      undefined,
      () => 1_900_000_000_001,
    );
    await durableKernel.initialize({
      sessionId: identity("sess"),
      tenantId: identity("tenant"),
      userId: identity("subject"),
      workspaceId: identity("ws"),
      runtimeRevisionDigest: `sha256:${"1".repeat(64)}` as Digest,
      policySnapshotDigest: `sha256:${"2".repeat(64)}` as Digest,
      emergencyOverlayDigest: `sha256:${"3".repeat(64)}` as Digest,
      engineKind: "low-level",
      adapterAbiVersion: 1,
      checkpointSchemaVersion: 1,
      placementGeneration: 5,
      sandboxGeneration: 6,
      authorizationGeneration: 7,
    });
    const input = { message: "claim through authenticated ingress" };
    const genesisPayload = new Uint8Array([0]);
    const genesis: AgentCheckpoint = {
      kind: "genesis",
      engineKind: "low-level",
      adapterAbiVersion: 1,
      checkpointSchemaVersion: 1,
      runtimeRevisionDigest: `sha256:${"1".repeat(64)}` as Digest,
      sessionId: identity("sess"),
      turnId: identity("turn"),
      checkpointSequence: 0,
      predecessorDigest: null,
      payloadEncoding: "opaque-v1",
      payloadBytes: genesisPayload,
      payloadDigest: await digestBytes(genesisPayload),
    };
    await durableKernel.execute({
      kind: "enqueue_turn",
      commandId: "ingress-enqueue",
      expectedEventSequence: 0,
      transactionTime: 1_900_000_000_000,
      turnId: identity("turn"),
      input,
      inputDigest: await turnInputDigest(input),
      genesisCheckpoint: genesis,
      turnLeaseGeneration: 4,
      leaseExpiresAt: 1_900_000_060_001,
    });
    const admitted = await durableKernel.query(null, (state) => state);
    if (admitted.activeTurn === null) throw new Error("active turn required");
    const effectPayload = new Uint8Array([1]);
    const effectRequest = {
      service: "executor" as const,
      operation: "process.spawn",
      replayPolicy: "idempotency-key" as const,
      payload: { argv: ["true"] },
    };
    await durableKernel.execute({
      kind: "commit_engine_step",
      commandId: "ingress-prepare",
      expectedEventSequence: admitted.eventSequence,
      turnId: identity("turn"),
      fence: {
        turnLeaseGeneration: 4,
        placementGeneration: 5,
        sandboxGeneration: 6,
        authorizationGeneration: 7,
      },
      transactionTime: 1_900_000_000_000,
      consumedSettlementEffectId: null,
      effectIdentity: {
        effectId: identity("effect"),
        invocationId: identity("inv"),
      },
      step: {
        kind: "effect_request",
        checkpoint: {
          kind: "engine",
          engineKind: admitted.engineKind,
          adapterAbiVersion: admitted.adapterAbiVersion,
          checkpointSchemaVersion: admitted.checkpointSchemaVersion,
          runtimeRevisionDigest: admitted.runtimeRevisionDigest,
          sessionId: admitted.sessionId,
          turnId: identity("turn"),
          checkpointSequence: 1,
          predecessorDigest: await checkpointDigest(admitted.activeTurn.checkpoint),
          payloadEncoding: "opaque-v1",
          payloadBytes: effectPayload,
          payloadDigest: await digestBytes(effectPayload),
        },
        request: {
          ...effectRequest,
          requestDigest: await effectRequestDigest(effectRequest),
        },
      },
    });
    const prepared = await durableKernel.query(null, (state) => state);
    const effect = prepared.effects[0];
    if (effect === undefined) throw new Error("prepared effect required");
    const dispatched = await durableKernel.execute({
      kind: "dispatch_effect",
      commandId: "ingress-dispatch",
      expectedEventSequence: prepared.eventSequence,
      turnId: identity("turn"),
      effectId: effect.effectId,
      invocationId: effect.invocationId,
      requestDigest: effect.requestDigest,
      fence: {
        turnLeaseGeneration: 4,
        placementGeneration: 5,
        sandboxGeneration: 6,
        authorizationGeneration: 7,
      },
      transactionTime: 1_900_000_000_000,
      deadline: 1_900_000_060_000,
      providerRequestId: identity("req", 70),
      providerRouteDigest: ROUTE_DIGEST as Digest,
    });
    if (dispatched.outcome.kind !== "effect_dispatched") {
      throw new Error("dispatch permit required");
    }
    const dispatchState = await durableKernel.query(null, (state) => state);
    const dispatchedEffect = dispatchState.effects[0];
    if (dispatchedEffect === undefined) throw new Error("dispatched effect required");
    const queuedInput = { message: "queued between dispatch and provider start" };
    const queuedPayload = new Uint8Array([2]);
    await durableKernel.execute({
      kind: "enqueue_turn",
      commandId: "ingress-enqueue-after-dispatch",
      expectedEventSequence: dispatchState.eventSequence,
      transactionTime: 1_900_000_000_001,
      turnId: identity("turn", 1),
      input: queuedInput,
      inputDigest: await turnInputDigest(queuedInput),
      genesisCheckpoint: {
        ...genesis,
        turnId: identity("turn", 1),
        payloadBytes: queuedPayload,
        payloadDigest: await digestBytes(queuedPayload),
      },
      turnLeaseGeneration: 8,
      leaseExpiresAt: 1_900_000_060_001,
    });
    const advancedState = await durableKernel.query(null, (state) => state);
    expect(advancedState.eventSequence).toBe(dispatchState.eventSequence + 1);
    const basePayload = {
      ...claimPayload(),
      expectedEventSequence: dispatchState.eventSequence,
      requestDigest: dispatchedEffect.requestDigest,
      dispatchAttempt: dispatchedEffect.dispatchAttempt,
      dispatchPermitClaims: dispatched.outcome.dispatchPermitClaims,
    };

    let calls = 0;
    const capturedCommands: Record<string, unknown>[] = [];
    const stub: SessionStub = {
      executeSessionCommand: async (unknownRequest) => {
        calls += 1;
        const envelope = unknownRequest as {
          requestId: string;
          payload: Record<string, unknown>;
        };
        capturedCommands.push(structuredClone(envelope.payload));
        const result = await durableKernel.execute(
          envelope.payload as unknown as SessionCommand,
        );
        return {
          protocol: HOST_PROTOCOL,
          major: 1,
          minor: 0,
          schemaDigest: HOST_SCHEMA_DIGEST,
          requestId: envelope.requestId,
          payload: { ok: true, result },
        };
      },
    };
    const requests = await Promise.all(Array.from({ length: 64 }, async (_, index) => {
      const payload = { ...basePayload, requestId: identity("req", index) };
      return { payload, ...await requestFromPayload(payload) };
    }));
    const responses = await Promise.all(
      requests.map(({ request }) => invoke(request, environment(stub))),
    );
    const decoded = await Promise.all(responses.map((response, index) =>
      decodedSignedResponse(response, requests[index]!.body, requests[index]!.payload.requestId)
    ));

    expect(calls).toBe(64);
    expect(capturedCommands).toHaveLength(64);
    expect(capturedCommands.every((command) =>
      JSON.stringify(command) === JSON.stringify(capturedCommands[0])
    )).toBe(true);
    expect(responses.every((response) => response.status === 200)).toBe(true);
    expect(decoded.filter((value) => {
      const envelope = value as { payload: { result: { outcome: { fresh: boolean } } } };
      return envelope.payload.result.outcome.fresh;
    })).toHaveLength(1);
    const durable = await durableKernel.query(null, (state) => state);
    expect(durable.eventSequence).toBe(advancedState.eventSequence + 1);
    expect(durable.queuedTurns.map((turn) => turn.turnId)).toEqual([
      identity("turn", 1),
    ]);
    expect(durable.commandReceipts.filter((receipt) =>
      receipt.outcome.kind === "dispatch_start_claimed"
    )).toHaveLength(1);
    expect(durable.effects[0]?.lastDispatch?.start).toMatchObject({
      commandDigest: COMMAND_DIGEST,
      claimedEventSequence: advancedState.eventSequence + 1,
      providerRouteDigest: ROUTE_DIGEST,
    });
  });

  it("rejects caller time, extra fields, cross-field relabels, and malformed claims as signed failures", async () => {
    const base = claimPayload();
    const cases: readonly Record<string, unknown>[] = [
      { ...base, transactionTime: 1 },
      { ...base, sessionId: identity("sess", 1) },
      { ...base, expectedEventSequence: Number.MAX_SAFE_INTEGER },
      { ...base, fence: { ...base.fence, placementGeneration: 99 } },
      {
        ...base,
        dispatchPermitClaims: { ...base.dispatchPermitClaims, providerRouteDigest: COMMAND_DIGEST },
      },
    ];

    for (const payload of cases) {
      let calls = 0;
      const { request, body } = await requestFromPayload(payload);
      const response = await invoke(request, environment({
        executeSessionCommand: async () => {
          calls += 1;
          throw new Error("must not execute");
        },
      }));
      expect(response.status).toBe(400);
      expect(calls).toBe(0);
      expect(await decodedSignedResponse(response, body, base.requestId)).toMatchObject({
        schemaDigest: HOST_SCHEMA_DIGEST,
        requestId: base.requestId,
        payload: { ok: false, error: { code: "INVALID_ARGUMENT" } },
      });
    }
  });

  it("binds authorization to the exact path and claim MAC domain", async () => {
    const payload = claimPayload();
    const wrongPath = "/circulusd/state/v1/session-dispatch-starts:claim";
    const wrongRoute = await requestFromPayload(payload, { path: wrongPath });
    const wrongRouteResponse = await invoke(wrongRoute.request, environment({}));
    expect(wrongRouteResponse.status).toBe(404);
    expectUnsigned(wrongRouteResponse);

    const readDomainSignatureBody = encodeCanonicalCbor(payload);
    const readKey = await directionalKey(CLAIM_KEY, "request");
    const readDomainSignature = hex(await hmac(readKey, lengthPrefixed([
      text("circulusd.state-ingress.request.v1"),
      text(CLAIM_KEY_ID),
      text("POST"),
      text(INGRESS_PATH),
      await sha256(readDomainSignatureBody),
    ])));
    const wrongDomain = await requestFromPayload(payload, { signature: readDomainSignature });
    const wrongDomainResponse = await invoke(wrongDomain.request, environment({}));
    expect(wrongDomainResponse.status).toBe(401);
    expectUnsigned(wrongDomainResponse);
  });

  it("returns a signed failure instead of forwarding a non-claim Host success", async () => {
    const payload = claimPayload();
    const { request, body } = await requestFromPayload(payload);
    const response = await invoke(request, environment({
      executeSessionCommand: async () => ({
        protocol: HOST_PROTOCOL,
        major: 1,
        minor: 0,
        schemaDigest: HOST_SCHEMA_DIGEST,
        requestId: payload.requestId,
        payload: {
          ok: true,
          result: {
            outcome: { kind: "effect_dispatched" },
            version: 13,
            replayed: false,
          },
        },
      }),
    }));

    expect(response.status).toBe(502);
    expect(await decodedSignedResponse(response, body, payload.requestId)).toMatchObject({
      schemaDigest: HOST_SCHEMA_DIGEST,
      payload: { ok: false, error: { code: "INTERNAL_ERROR" } },
    });
  });

  it("rejects a Host success whose claimed sequence does not follow the dispatch receipt", async () => {
    const payload = claimPayload();
    const { request, body } = await requestFromPayload(payload);
    const response = await invoke(request, environment({
      executeSessionCommand: async (unknownRequest) => {
        const envelope = unknownRequest as {
          requestId: string;
          payload: Record<string, unknown>;
        };
        return hostSuccess(envelope.requestId, envelope.payload, true, {
          claimedEventSequence: payload.expectedEventSequence,
          version: payload.expectedEventSequence,
        });
      },
    }));

    expect(response.status).toBe(502);
    expect(await decodedSignedResponse(response, body, payload.requestId)).toMatchObject({
      schemaDigest: HOST_SCHEMA_DIGEST,
      payload: { ok: false, error: { code: "INTERNAL_ERROR" } },
    });
  });
});
