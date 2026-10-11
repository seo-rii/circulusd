import { createHash, createHmac } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { decodeCanonicalCbor, digestStructuredValue, encodeCanonicalCbor, type AgentCheckpoint,
  type EngineStepResult, type NormalizedValue } from "@circulusd/protocol-types";
import { LowLevelPiAgentEngine, createOpaqueTurnAuthority, createPiAgentCoreFactory,
  createPiAgentCoreInitialState, decodePiAgentCoreModelContext } from "../../pi-runtime/src/index.ts";
import { SessionCell } from "../src/host/cells.ts";
import { sessionCellName } from "../src/host/names.ts";
import { HOST_RPC_CONTRACTS, type HostRpcOperation } from "../src/host/rpc.ts";
import { RestartableDurableStorage } from "./support/restartable-durable-storage.ts";
import worker from "../src/host/worker.ts";

const id = (prefix: string) => `${prefix}_${"A".repeat(26)}`;
const NOW = 1_700_000_000_000;
const digest = (character: string) => `sha256:${character.repeat(64)}` as const;
const input = { messages: [{ role: "user", content: "First public message." }, { role: "user", content: "Second public message." }] };
const path = "/circulusd/state/v1/session-turn:plan";
const contentType = "application/vnd.circulusd.state-turn-plan-ingress+cbor";
const descriptor = "circulus.state-turn-plan-ingress.v1alpha1|major=1|minor=0|scoped-session-admission-plan|fields=protocol,major,minor,schemaDigest,requestId,sentAtUnixMs,tenantId,actorSubjectId,sessionId,expectedAuthorizationGeneration,proposedTurnId,input,inputDigest,idempotencyKeyDigest,requestDigest|maxBytes=2097152|maxDepth=72|maxItems=100000";
const schemaDigest = `sha256:${createHash("sha256").update(descriptor).digest("hex")}`;
const rootKey = Buffer.alloc(32, 0x51), keyId = "admission-plan-1";
const fixturePath = new URL("../../../packages/protocol-types/fixtures/state-app-admission-plan-v1alpha1.json", import.meta.url);
const hex = (value: NormalizedValue) => Buffer.from(encodeCanonicalCbor(value)).toString("hex");
const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest();
function mac(direction: "request" | "response", parts: (string | Uint8Array)[]) {
  const key = createHmac("sha256", rootKey).update(`circulusd.state-ingress.key.${direction}.v1\0`).digest();
  return createHmac("sha256", key).update(Buffer.concat(parts.map((part) => {
    const bytes = typeof part === "string" ? Buffer.from(part) : part;
    const prefix = Buffer.alloc(4); prefix.writeUInt32BE(bytes.length);
    return Buffer.concat([prefix, bytes]);
  }))).digest("hex");
}
function envelope(operation: HostRpcOperation, payload: unknown) {
  return { protocol: "circulus.v1alpha1", major: 1, minor: 0,
    schemaDigest: HOST_RPC_CONTRACTS[operation].schemaDigest, requestId: id("req"), payload };
}
function engine() {
  return new LowLevelPiAgentEngine({ sessionId: id("sess"), runtimeRevisionDigest: digest("a"), adapterAbiVersion: 2, checkpointSchemaVersion: 2 },
    createPiAgentCoreFactory({ systemPrompt: "Test public admission without provider I/O.",
      model: { id: "admission-test-model", api: "circulusd-model-gateway", provider: "circulusd",
        reasoning: false, input: ["text"], contextWindow: 8192, maxTokens: 1024 }, tools: [] }));
}
async function setup(policy: unknown = { turnLeaseTTLms: 120_000 }) {
  const storage = new RestartableDurableStorage();
  const physical = (name: string) => ({ toString: () => name, equals: (other: unknown) => String(other) === name });
  const env = { SESSION_CELL: { idFromName: physical }, CIRCULUSD_STATE_ADMISSION_POLICY: policy };
  const cell = new SessionCell({ storage, id: physical(sessionCellName(id("tenant"), id("sess"))) } as never, env as never, () => NOW);
  const initialized = await cell.initializeSession(envelope("session.initialize", { tenantId: id("tenant"), userId: id("subject"),
    workspaceId: id("ws"), sessionId: id("sess"), runtimeRevisionDigest: digest("a"), policySnapshotDigest: digest("b"),
    emergencyOverlayDigest: digest("c"), engineKind: "low-level", adapterAbiVersion: 2, checkpointSchemaVersion: 2,
    placementGeneration: 1, sandboxGeneration: 1, authorizationGeneration: 7 }));
  expect(initialized.payload.ok).toBe(true);
  const request = { tenantId: id("tenant"), actorSubjectId: id("subject"), sessionId: id("sess"), expectedAuthorizationGeneration: 7,
    proposedTurnId: id("turn"), input, inputDigest: await digestStructuredValue("circulusd.session.turn-input", 1, input),
    idempotencyKeyDigest: digest("d"), requestDigest: await digestStructuredValue("circulusd.public.turn.create", 1,
      { sessionId: id("sess"), messages: input.messages.map((message) => [message.role, message.content]) }) };
  return { cell, storage, request };
}

afterEach(() => vi.restoreAllMocks());

describe("authoritative Session admission planning", () => {
  it("produces signed cross-language plans and an actual executable cold Pi genesis", async () => {
    vi.spyOn(Date, "now").mockReturnValue(NOW);
    const { cell, request } = await setup();
    const env = { CIRCULUSD_STATE_ADMISSION_CURRENT_KEY_ID: keyId, CIRCULUSD_STATE_ADMISSION_CURRENT_KEY: rootKey.toString("hex"),
      SESSION_CELL: { getByName: vi.fn(() => cell) } };
    const fullRequest = { protocol: "circulus.state-turn-plan-ingress.v1alpha1", major: 1, minor: 0,
      schemaDigest, requestId: id("req"), sentAtUnixMs: NOW, ...request };
    const encodedRequest = encodeCanonicalCbor(fullRequest);
    const requestMac = mac("request", ["circulusd.state-turn-plan-ingress.request.v1", keyId, "POST", path, hash(encodedRequest)]);
    const response = await worker.fetch(new Request(`http://127.0.0.1${path}`, { method: "POST", body: encodedRequest,
      headers: { "content-type": contentType, "x-circulus-state-key-id": keyId, "x-circulus-state-signature": requestMac } }), env as never);
    expect(response.status).toBe(200);
    const responseBytes = new Uint8Array(await response.arrayBuffer());
    const decoded = decodeCanonicalCbor(responseBytes) as { payload: { result: Record<string, NormalizedValue> } };
    const plan = decoded.payload.result;
    expect(plan).toMatchObject({ kind: "new", expectedEventSequence: 0, turnLeaseGeneration: 1, leaseExpiresAt: NOW + 120_000, plannedAt: NOW });
    const responseMac = mac("response", ["circulusd.state-turn-plan-ingress.response.v1", keyId, id("req"), hash(encodedRequest), "200", contentType, hash(responseBytes)]);
    expect(response.headers.get("x-circulus-state-signature")).toBe(responseMac);
    const genesis = await engine().createGenesisCheckpoint({ turnId: id("turn"), input, initialCoreState: createPiAgentCoreInitialState() });
    const first = await engine().step({ authority: createOpaqueTurnAuthority(new Uint8Array([1, 2, 3])),
      checkpoint: decodeCanonicalCbor(encodeCanonicalCbor(genesis)) as unknown as AgentCheckpoint });
    expect(first.kind).toBe("effect_request");
    if (first.kind !== "effect_request") throw new Error("public input did not execute");
    const context = decodePiAgentCoreModelContext((first.request.payload as { context: NormalizedValue }).context);
    expect(context.messages).toEqual(input.messages.map((message) => ({ role: "user", content: message.content, timestamp: 0 })));
    const fixture = { descriptor, schemaDigest, path, method: "POST", responseStatus: 200, contentType, keyId, rootKeyHex: rootKey.toString("hex"),
      request: fullRequest, response: decodeCanonicalCbor(responseBytes), requestCborHex: Buffer.from(encodedRequest).toString("hex"),
      responseCborHex: Buffer.from(responseBytes).toString("hex"), requestMacHex: requestMac, responseMacHex: responseMac,
      genesisCborHex: hex(genesis), firstBoundaryCborHex: hex(first as EngineStepResult) };
    if (process.env.UPDATE_ADMISSION_PLAN_FIXTURE === "1") writeFileSync(fixturePath, `${JSON.stringify(fixture, null, 2)}\n`);
    expect(fixture).toEqual(JSON.parse(readFileSync(fixturePath, "utf8")));
  });

  it("requires immutable host lease policy and checks full digests/scope before archive reads", async () => {
    const absent = await setup(undefined);
    // setup's default argument is explicit; make an absent-policy Cell on the same durable state.
    const physical = (name: string) => ({ toString: () => name, equals: (other: unknown) => String(other) === name });
    const missing = new SessionCell({ storage: absent.storage, id: physical(sessionCellName(id("tenant"), id("sess"))) } as never,
      { SESSION_CELL: { idFromName: physical } } as never, () => NOW);
    const unavailable = await missing.planSessionTurnAdmission(envelope("session.execute", absent.request));
    expect(unavailable.payload).toMatchObject({ ok: false, error: { code: "FAILED_PRECONDITION" } });
    for (const [field, value, code] of [["tenantId", id("tenant").replace(/A$/, "E"), "PERMISSION_DENIED"],
      ["actorSubjectId", id("subject").replace(/A$/, "E"), "PERMISSION_DENIED"],
      ["sessionId", id("sess").replace(/A$/, "E"), "PERMISSION_DENIED"],
      ["expectedAuthorizationGeneration", 6, "STALE_GENERATION"], ["inputDigest", digest("e"), "DIGEST_MISMATCH"]] as const) {
      const result = await absent.cell.planSessionTurnAdmission(envelope("session.execute", { ...absent.request, [field]: value }));
      expect(result.payload).toMatchObject({ ok: false, error: { code } });
    }
    const before = await absent.cell.planSessionTurnAdmission(envelope("session.execute", absent.request));
    const after = await absent.cell.planSessionTurnAdmission(envelope("session.execute", absent.request));
    expect(before).toEqual(after);
  });

  it("replays the original admission and rejects changed semantic input", async () => {
    const { cell, request } = await setup();
    const planned = await cell.planSessionTurnAdmission(envelope("session.execute", request));
    if (!planned.payload.ok) throw new Error("missing plan");
    const plan = planned.payload.result as Record<string, NormalizedValue>;
    const genesis = await engine().createGenesisCheckpoint({ turnId: id("turn"), input, initialCoreState: createPiAgentCoreInitialState() });
    const admitted = await cell.executeSessionCommand(envelope("session.execute", { kind: "enqueue_turn", commandId: plan.commandId,
      expectedEventSequence: plan.expectedEventSequence, transactionTime: NOW, turnId: id("turn"), input, inputDigest: request.inputDigest,
      genesisCheckpoint: genesis, turnLeaseGeneration: plan.turnLeaseGeneration, leaseExpiresAt: plan.leaseExpiresAt,
      publicAdmission: { tenantId: request.tenantId, actorSubjectId: request.actorSubjectId, authorizationGeneration: 7,
        idempotencyKeyDigest: request.idempotencyKeyDigest, requestDigest: request.requestDigest } }));
    expect(admitted.payload.ok).toBe(true);
    const replay = await cell.planSessionTurnAdmission(envelope("session.execute", { ...request, proposedTurnId: id("turn").replace(/A$/, "E") }));
    expect(replay.payload).toMatchObject({ ok: true, result: { kind: "replay", admission: { turnId: id("turn"), turnSequence: 0, activated: true, version: 1 } } });
    const changed = { messages: [{ role: "user", content: "Different prompt." }] };
    const conflict = await cell.planSessionTurnAdmission(envelope("session.execute", { ...request, input: changed,
      inputDigest: await digestStructuredValue("circulusd.session.turn-input", 1, changed),
      requestDigest: await digestStructuredValue("circulusd.public.turn.create", 1, { sessionId: id("sess"), messages: [["user", "Different prompt."]] }) }));
    expect(conflict.payload).toMatchObject({ ok: false, error: { code: "IDEMPOTENCY_CONFLICT" } });
    const stale = await cell.planSessionTurnAdmission(envelope("session.execute", { ...request, expectedAuthorizationGeneration: 6 }));
    expect(stale.payload).toMatchObject({ ok: false, error: { code: "STALE_GENERATION" } });
  });

  it("keeps authenticated admission replay across receipt compaction and a cold Cell", async () => {
    const { cell, storage, request } = await setup();
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    for (let index = 0; index < 36; index++) {
      const turnId = `turn_${"A".repeat(23)}${alphabet[Math.floor(index / 32)]}${alphabet[index % 32]}A`;
      const next = { ...request, proposedTurnId: turnId,
        idempotencyKeyDigest: index === 0 ? request.idempotencyKeyDigest : await digestStructuredValue("admission-test-key", 1, { index }) };
      const response = await cell.planSessionTurnAdmission(envelope("session.execute", next));
      if (!response.payload.ok) throw new Error(JSON.stringify(response.payload));
      const plan = response.payload.result as Record<string, NormalizedValue>;
      const genesis = await engine().createGenesisCheckpoint({ turnId, input, initialCoreState: createPiAgentCoreInitialState() });
      const result = await cell.executeSessionCommand(envelope("session.execute", { kind: "enqueue_turn", commandId: plan.commandId,
        expectedEventSequence: plan.expectedEventSequence, transactionTime: NOW, turnId, input, inputDigest: next.inputDigest,
        genesisCheckpoint: genesis, turnLeaseGeneration: plan.turnLeaseGeneration, leaseExpiresAt: plan.leaseExpiresAt,
        publicAdmission: { tenantId: next.tenantId, actorSubjectId: next.actorSubjectId, authorizationGeneration: 7,
          idempotencyKeyDigest: next.idempotencyKeyDigest, requestDigest: next.requestDigest } }));
      expect(result.payload, JSON.stringify(result.payload)).toMatchObject({ ok: true });
    }
    const physical = (name: string) => ({ toString: () => name, equals: (other: unknown) => String(other) === name });
    const restarted = new SessionCell({ storage: storage.restart(), id: physical(sessionCellName(id("tenant"), id("sess"))) } as never,
      { SESSION_CELL: { idFromName: physical }, CIRCULUSD_STATE_ADMISSION_POLICY: { turnLeaseTTLms: 120_000 } } as never, () => NOW);
    const replay = await restarted.planSessionTurnAdmission(envelope("session.execute", request));
    expect(replay.payload).toMatchObject({ ok: true, result: { kind: "replay", admission: { turnId: id("turn"), turnSequence: 0, activated: true, version: 36 } } });
    const stale = await restarted.planSessionTurnAdmission(envelope("session.execute", { ...request, expectedAuthorizationGeneration: 6 }));
    expect(stale.payload).toMatchObject({ ok: false, error: { code: "STALE_GENERATION" } });
  });

  it("lets the same Session CAS reject a plan superseded by another admission", async () => {
    const { cell, request } = await setup();
    const first = await cell.planSessionTurnAdmission(envelope("session.execute", request));
    const other = { ...request, proposedTurnId: id("turn").replace(/A$/, "E"), idempotencyKeyDigest: digest("e") };
    const second = await cell.planSessionTurnAdmission(envelope("session.execute", other));
    if (!first.payload.ok || !second.payload.ok) throw new Error("missing CAS plan");
    const admit = async (plan: unknown, next: typeof request) => {
      const value = plan as Record<string, NormalizedValue>;
      const genesis = await engine().createGenesisCheckpoint({ turnId: next.proposedTurnId, input, initialCoreState: createPiAgentCoreInitialState() });
      return cell.executeSessionCommand(envelope("session.execute", { kind: "enqueue_turn", commandId: value.commandId,
        expectedEventSequence: value.expectedEventSequence, transactionTime: NOW, turnId: next.proposedTurnId, input, inputDigest: next.inputDigest,
        genesisCheckpoint: genesis, turnLeaseGeneration: value.turnLeaseGeneration, leaseExpiresAt: value.leaseExpiresAt,
        publicAdmission: { tenantId: next.tenantId, actorSubjectId: next.actorSubjectId, authorizationGeneration: 7,
          idempotencyKeyDigest: next.idempotencyKeyDigest, requestDigest: next.requestDigest } }));
    };
    expect((await admit(second.payload.result, other)).payload).toMatchObject({ ok: true });
    expect((await admit(first.payload.result, request)).payload).toMatchObject({ ok: false, error: { code: "CONFLICT" } });
  });
});
