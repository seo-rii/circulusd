import { readFileSync, writeFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { decodeCanonicalCbor, encodeCanonicalCbor, type AgentCheckpoint, type Digest, type EngineStepResult, type NormalizedValue } from "@circulusd/protocol-types";
import { SessionCell, sessionCellName } from "../src/host/index.ts";
import { HOST_RPC_CONTRACTS, type HostRpcOperation, type HostRpcResponse } from "../src/host/rpc.ts";
import {
  effectRequestDigest, turnInputDigest, type SessionBrokerEngineGrant, type SessionBrokerPreparationPermit,
  type SessionBrokerRequest, type SessionBrokerSnapshot, type SessionBrokerStepReceipt, type SessionBrokerTurn,
} from "../src/session/index.ts";
import { RestartableDurableStorage } from "./support/restartable-durable-storage.ts";

const id = (prefix: string) => `${prefix}_${"A".repeat(26)}`;
const digest = (character: string): Digest => `sha256:${character.repeat(64)}`;
const authority = { tenantId: id("tenant"), workspaceId: id("ws"), sessionId: id("sess"), actorSubjectId: id("subject"), expectedAuthorizationGeneration: 1 };
const policy = { engineStepLimits: { maximumEvents: 1, maximumEphemeralBytes: 1_048_576, maximumWallClockMs: 5_000 }, preparationTTLms: 30_000 };
// A fixed future authority clock also keeps Go context.WithDeadline live when
// the shared vectors exercise its real Coordinator rather than a mock clock.
const NOW = 4_102_444_800_000;
const path = new URL("../../../packages/protocol-types/fixtures/state-app-broker-lifecycle-v1.json", import.meta.url);
const pi = JSON.parse(readFileSync(new URL("../../../packages/protocol-types/fixtures/stateapp-pi-codec-v1.json", import.meta.url), "utf8")) as {
  checkpoints: Array<{ wireHex: string }>; boundaries: Array<{ wireHex: string }>; settlements: Array<{ wireHex: string }>;
};
const decode = (hex: string) => decodeCanonicalCbor(new Uint8Array(Buffer.from(hex, "hex")));
const hex = (value: unknown) => Buffer.from(encodeCanonicalCbor(value as NormalizedValue)).toString("hex");

async function vectors() {
  const responses: Array<{ name: string; operation: string; requestCborHex: string; responseCborHex: string }> = [];
  const blobs = new Map<Digest, { digest: Digest; encodedBytes: number; bytes: { hex: string } }>();
  async function scenario(label: string, replayPolicy?: "safe" | "confirm" | "never", dispatchNow = true) {
    const storage = new RestartableDurableStorage();
    const physical = (name: string) => ({ toString: () => name, equals: (other: unknown) => String(other) === name });
    let clock = NOW;
    const cell = new SessionCell({ storage, id: physical(sessionCellName(authority.tenantId, authority.sessionId)) } as never,
      { SESSION_CELL: { idFromName: physical }, CIRCULUSD_STATE_BROKER_POLICY: policy } as never, () => clock);
    async function rpc<Result>(operation: HostRpcOperation, payload: unknown, invoke: (request: unknown) => Promise<HostRpcResponse<Result>>): Promise<Result> {
      const response = await invoke({ protocol: "circulus.v1alpha1", major: 1, minor: 0,
        schemaDigest: HOST_RPC_CONTRACTS[operation].schemaDigest, requestId: id("req"), payload });
      expect(response.payload, JSON.stringify(response.payload)).toMatchObject({ ok: true });
      if (!response.payload.ok) throw new Error(response.payload.error.code);
      return response.payload.result as Result;
    }
    const control = { serviceBinding: "state", tenantId: authority.tenantId, actorUserId: authority.actorSubjectId, subjectKind: "session", subjectId: authority.sessionId,
      roles: ["user"], permissions: ["session.read"], authorizationGeneration: 1, currentAuthorizationGeneration: 1, issuedAt: NOW - 1, expiresAt: NOW + 120_000 };
    async function collect(value: unknown): Promise<void> {
      if (value === null || typeof value !== "object" || value instanceof Uint8Array) return;
      if (Array.isArray(value)) { for (const item of value) await collect(item); return; }
      const record = value as Record<string, unknown>;
      const reference = record.encoding === "canonical-cbor-v1" ? record.digest : "payloadSize" in record ? record.payloadDigest : undefined;
      if (typeof reference === "string" && !blobs.has(reference as Digest)) {
        const blob = await rpc("session.read-blob", { authority: control, now: NOW, digest: reference }, (request) => cell.readSessionBlob(request));
        expect(blob).not.toBeNull();
        blobs.set(reference as Digest, { digest: reference as Digest, encodedBytes: blob!.encodedBytes, bytes: { hex: Buffer.from(blob!.bytes).toString("hex") } });
      }
      for (const child of Object.values(record)) await collect(child);
    }
    async function call<Result>(name: string, request: SessionBrokerRequest): Promise<Result> {
      const result = await rpc("session.execute", { authority: structuredClone(authority), ...request }, (value) => cell.brokerSession(value));
      responses.push({ name: `${label}.${name}`, operation: request.operation, requestCborHex: hex(request), responseCborHex: hex(result) });
      await collect(result);
      return result as Result;
    }
    const genesis = decode(pi.checkpoints[0]!.wireHex) as unknown as AgentCheckpoint;
    await rpc("session.initialize", { sessionId: authority.sessionId, tenantId: authority.tenantId, userId: authority.actorSubjectId, workspaceId: authority.workspaceId,
      runtimeRevisionDigest: genesis.runtimeRevisionDigest, policySnapshotDigest: digest("b"), emergencyOverlayDigest: digest("c"), engineKind: genesis.engineKind,
      adapterAbiVersion: genesis.adapterAbiVersion, checkpointSchemaVersion: genesis.checkpointSchemaVersion, placementGeneration: 1, sandboxGeneration: 1, authorizationGeneration: 1 }, (request) => cell.initializeSession(request));
    const input = { prompt: "Echo 1.25", timestamp: 1_700_000_000_000 };
    await rpc("session.execute", { kind: "enqueue_turn", commandId: `${label}-admit`, expectedEventSequence: 0, transactionTime: NOW, turnId: id("turn"), input,
      inputDigest: await turnInputDigest(input), genesisCheckpoint: genesis, turnLeaseGeneration: 1, leaseExpiresAt: NOW + 120_000 }, (request) => cell.executeSessionCommand(request));
    const read = (name: string) => call<SessionBrokerTurn>(name, { operation: "read-turn", body: {} });
    const snapshot = (turn: SessionBrokerTurn): SessionBrokerSnapshot => ({ turnId: turn.turnId!, eventSequence: turn.eventSequence,
      checkpointDigest: turn.checkpointDigest!, fence: turn.fence, activeEffect: turn.activeEffect === null ? null : {
        effectId: turn.activeEffect.effectId, invocationId: turn.activeEffect.invocationId, requestDigest: turn.activeEffect.requestDigest,
        phase: turn.activeEffect.phase, dispatchAttempt: turn.activeEffect.dispatchAttempt } });
    const active = await read("active");
    const grant = await call<SessionBrokerEngineGrant>("acquire", { operation: "acquire-step", body: { snapshot: snapshot(active), operationKey: `${label}-acquire`, nowUnixMs: NOW, budget: policy.engineStepLimits } });
    let step = decode(pi.boundaries[0]!.wireHex) as unknown as EngineStepResult;
    if (step.kind !== "effect_request") throw new Error("expected Pi model boundary");
    if (replayPolicy !== undefined) {
      const request = { ...step.request, replayPolicy };
      step = { ...step, request: { ...request, requestDigest: await effectRequestDigest(request) } };
    }
    const committed = await call<SessionBrokerStepReceipt>("commit", { operation: "commit-step", body: { snapshot: snapshot(active), operationKey: `${label}-commit`,
      requestDigest: digest("d"), permitOpaque: grant.opaque, nowUnixMs: NOW, step } });
    const prepared = await read("prepared");
    const effect = prepared.activeEffect!;
    const key = { turnId: effect.turnId, effectId: effect.effectId, invocationId: effect.invocationId, requestDigest: effect.requestDigest };
    async function abort() {
      const turn = await read("before-abort");
      await rpc("session.execute", { kind: "request_abort", commandId: `${label}-abort`, expectedEventSequence: turn.eventSequence,
        turnId: turn.turnId, fence: turn.fence, transactionTime: NOW, reason: "cancel" }, (request) => cell.executeSessionCommand(request));
    }
    const dispatch = dispatchNow ? await call<Record<string, NormalizedValue>>("dispatch", { operation: "dispatch", body: { snapshot: snapshot(prepared), key,
      operationKey: `${label}-dispatch`, operationDigest: digest("e"), preparationOpaque: committed.preparation!.opaque, providerRequestId: id("req"),
      providerRouteDigest: digest("f"), nowUnixMs: NOW, deadlineUnixMs: committed.preparation!.deadline } }) : null;
    const current = dispatchNow ? await read("dispatched") : prepared;
    return { call, read, snapshot, key, dispatch: dispatch!, current, abort, preparation: committed.preparation!, advance: (elapsed: number) => { clock += elapsed; } };
  }
  const main = await scenario("success");
  const claimBody = { snapshot: main.snapshot(main.current), key: main.key, dispatchOpaque: main.dispatch.opaque as Uint8Array, commandDigest: digest("7"), nowUnixMs: NOW };
  await main.call("start", { operation: "claim-start", body: claimBody });
  await main.call("start-replay", { operation: "claim-start", body: claimBody });
  await main.call("confirmation", { operation: "confirm", body: { snapshot: main.snapshot(await main.read("started")), key: main.key, operationKey: "success-confirm",
    operationDigest: digest("8"), dispatchAttempt: 1, providerRequestId: id("req"), providerRouteDigest: digest("f"), externalCommitId: id("commit"), resultRef: id("artifact") } });
  const settlement = decode(pi.settlements[0]!.wireHex) as { outcome: { kind: "success"; result: NormalizedValue } };
  await main.call("settlement", { operation: "settle", body: { snapshot: main.snapshot(await main.read("confirmed")), key: main.key,
    operationKey: "success-settle", operationDigest: digest("9"), dispatchAttempt: 1, externalCommitId: id("commit"), resultRef: id("artifact"), error: null, settlement: settlement.outcome } });
  await main.call("lookup-settlement", { operation: "lookup-operation", body: { kind: "settlement", operationKey: "success-settle", operationDigest: digest("9") } });
  await main.call("lookup-missing", { operation: "lookup-operation", body: { kind: "settlement", operationKey: "missing", operationDigest: digest("9") } });
  const settled = await main.read("settled");
  await main.call("resume-grant", { operation: "acquire-step", body: { snapshot: main.snapshot(settled), operationKey: "resume", nowUnixMs: NOW, budget: policy.engineStepLimits } });

  const failed = await scenario("error");
  const failedClaim = { snapshot: failed.snapshot(failed.current), key: failed.key,
    dispatchOpaque: failed.dispatch.opaque as Uint8Array, commandDigest: digest("7"), nowUnixMs: NOW };
  await failed.call("start", { operation: "claim-start", body: failedClaim });
  await failed.call("start-replay", { operation: "claim-start", body: failedClaim });
  const publicError = { code: 7, reason: "provider_failed", message: "Provider diagnostics: " + "x".repeat(8192),
    retryable: true, retryAfterMs: 500, metadata: { route: "original", diagnostic: "preserved" }, requestId: id("req") };
  await failed.call("confirmation", { operation: "confirm", body: { snapshot: failed.snapshot(await failed.read("started")),
    key: failed.key, operationKey: "error-confirm", operationDigest: digest("8"), dispatchAttempt: 1,
    providerRequestId: id("req"), providerRouteDigest: digest("f"), externalCommitId: id("commit"), resultRef: null } });
  await failed.call("settlement", { operation: "settle", body: { snapshot: failed.snapshot(await failed.read("confirmed")),
    key: failed.key, operationKey: "error-settle", operationDigest: digest("9"), dispatchAttempt: 1,
    externalCommitId: id("commit"), resultRef: null, error: publicError,
    settlement: { kind: "error", code: "effect.failed", message: "The effect failed.", retryable: true } } });
  await failed.call("lookup-settlement", { operation: "lookup-operation", body: { kind: "settlement", operationKey: "error-settle", operationDigest: digest("9") } });
  await failed.call("lookup-missing", { operation: "lookup-operation", body: { kind: "settlement", operationKey: "missing", operationDigest: digest("9") } });
  const failedSettled = await failed.read("settled");
  await failed.call("resume-grant", { operation: "acquire-step", body: { snapshot: failed.snapshot(failedSettled),
    operationKey: "resume-error", nowUnixMs: NOW, budget: policy.engineStepLimits } });

  const retry = await scenario("retry", "safe");
  const reservation = await retry.call<SessionBrokerPreparationPermit>("preparation", { operation: "prepare-retry", body: { snapshot: retry.snapshot(retry.current), key: retry.key,
    operationKey: "retry-prepare", operationDigest: digest("1"), nowUnixMs: NOW, deadlineUnixMs: NOW + 60_000, userConfirmed: false } });
  await retry.call("second-dispatch", { operation: "dispatch", body: { snapshot: retry.snapshot(retry.current), key: retry.key,
    operationKey: "retry-dispatch-2", operationDigest: digest("2"), preparationOpaque: reservation.opaque, providerRequestId: id("req"),
    providerRouteDigest: digest("f"), nowUnixMs: NOW, deadlineUnixMs: reservation.deadline } });
  const block = await scenario("blocked", "confirm");
  const error = { code: 7, reason: "UNCERTAIN", message: "Provider result is not available", retryable: false, retryAfterMs: 250,
    metadata: { route: "original" }, requestId: id("req") };
  await block.call("block", { operation: "block", body: { snapshot: block.snapshot(block.current), key: block.key, operationKey: "block", operationDigest: digest("3"), reason: error } });
  await block.call("lookup-block", { operation: "lookup-operation", body: { kind: "block", operationKey: "block", operationDigest: digest("3") } });
  const recovery = await scenario("recovery", "never");
  await recovery.call("settlement", { operation: "settle-recovery", body: { snapshot: recovery.snapshot(recovery.current), key: recovery.key,
    operationKey: "recovery-settle", operationDigest: digest("4"), kind: "interrupted_unknown", error } });
  for (const [label, phase, started] of [
    ["abort-prepared", "prepared", false], ["abort-blocked", "blocked", false],
    ["ledger-failed", "dispatched", false], ["ledger-failed-started", "dispatched", true],
  ] as const) {
    const source = await scenario(label, phase === "blocked" ? "confirm" : "safe", phase !== "prepared");
    if (started) await source.call("start", { operation: "claim-start", body: { snapshot: source.snapshot(source.current),
      key: source.key, dispatchOpaque: source.dispatch.opaque as Uint8Array, commandDigest: digest("7"), nowUnixMs: NOW } });
    if (phase === "blocked") await source.call("block", { operation: "block", body: { snapshot: source.snapshot(source.current),
      key: source.key, operationKey: `${label}-block`, operationDigest: digest("3"), reason: error } });
    const abort = phase !== "dispatched";
    if (abort) await source.abort();
    const before = await source.read("before-recovery");
    await source.call("settlement", { operation: "settle-recovery", body: { snapshot: source.snapshot(before), key: source.key,
      operationKey: `${label}-recover`, operationDigest: digest("4"), kind: abort ? "interrupted_unknown" : "failed", error: abort ? error : { ...error, reason: "r".repeat(300), message: "x".repeat(8192) } } });
    await source.read("settled");
  }
  const renewal = await scenario("renewal", "never", false);
  renewal.advance(policy.preparationTTLms + 1);
  const expired = await renewal.read("expired");
  const renewed = await renewal.call<SessionBrokerPreparationPermit>("preparation", { operation: "prepare-retry", body: {
    snapshot: renewal.snapshot(expired), key: renewal.key, operationKey: "renewal-recover:prepare", operationDigest: digest("5"),
    nowUnixMs: NOW + 30_001, deadlineUnixMs: NOW + 100_000, userConfirmed: false } });
  const renewedState = await renewal.read("renewed");
  await renewal.call("dispatch", { operation: "dispatch", body: { snapshot: renewal.snapshot(renewedState), key: renewal.key,
    operationKey: "renewal-dispatch", operationDigest: digest("e"), preparationOpaque: renewed.opaque, providerRequestId: id("req"),
    providerRouteDigest: digest("f"), nowUnixMs: NOW + 30_001, deadlineUnixMs: renewed.deadline } });
  const dispatchedRenewal = await renewal.read("dispatched");
  const start = { snapshot: renewal.snapshot(dispatchedRenewal), key: renewal.key,
    dispatchOpaque: dispatchedRenewal.dispatch!.opaque, commandDigest: digest("7"), nowUnixMs: NOW + 30_001 };
  await renewal.call("start", { operation: "claim-start", body: start });
  await renewal.call("start-replay", { operation: "claim-start", body: start });
  await renewal.read("started");
  return { version: 1, authority, policy, responses, blobs: [...blobs.values()].sort((a, b) => a.digest.localeCompare(b.digest)) };
}

describe("actual Session broker cross-language lifecycle", () => {
  it("matches original durable receipts, real Pi checkpoints and payload blobs", async () => {
    let seed = 0x5eed1234;
    const entropy = vi.spyOn(crypto, "getRandomValues").mockImplementation(<T extends ArrayBufferView | null>(array: T): T => {
      if (array === null) throw new TypeError("entropy array required");
      const bytes = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
      for (let index = 0; index < bytes.length; index += 1) {
        seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5;
        bytes[index] = seed >>> 24;
      }
      return array;
    });
    try {
      const actual = await vectors();
      if (process.env.CIRCULUSD_UPDATE_BROKER_GOLDEN === "1") writeFileSync(path, `${JSON.stringify(actual, null, 2)}\n`);
      expect(actual).toEqual(JSON.parse(readFileSync(path, "utf8")));
    } finally { entropy.mockRestore(); }
  }, 30_000);
});
