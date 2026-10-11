import {
  digestStructuredValue, encodeCanonicalCbor, externalizeAgentCheckpoint,
  parseAgentCheckpoint, parseExternalizedAgentCheckpoint,
  parseDigest, parseDispatchPermitClaims, type Digest, type NormalizedValue,
} from "@circulusd/protocol-types";
import {
  assertSessionCapacity, checkpointDigest, sessionReferencedBlobDigests, validateSessionState,
} from "./aggregate.ts";
import { compactSessionHistory } from "./history.ts";
import { readSessionPayload, storeSessionPayload, validateSessionPayloadRef } from "./payload.ts";
import { sessionError } from "./errors.ts";
import {
  assertSessionBrokerAuthority, brokerExact, brokerFence, brokerIdentifier, brokerInteger,
  brokerOpaque, parseSessionBrokerPolicy, parseSessionBrokerRequest,
  validateSessionBrokerCommandShape,
} from "./broker-validation.ts";
import {
  type SessionBrokerCommand, type SessionBrokerEngineGrant,
  type SessionBrokerPreparationPermit, type SessionBrokerReceiptKind, type SessionBrokerReceiptValue,
  type SessionBrokerStoredReceipt, type SessionBrokerState, type SessionBrokerSnapshot,
  type SessionBrokerTurn, type SessionBrokerPolicy, type SessionBrokerEffectKey,
  type SessionBrokerMutation, type SessionBrokerDispatchPermit,
  type SessionBrokerSettlementReceipt, type SessionBrokerOperationLookup,
  type SessionBrokerOperationReceipt,
} from "./broker-types.ts";
import type {
  ApplySessionCommandResult, SessionAggregateState, SessionApplyContext, SessionCommand,
  SessionEffect, SessionFence, StoredSessionCommandOutcome, StoredSessionCheckpoint,
} from "./types.ts";

type CoreCommand = Exclude<SessionCommand, { kind: "broker_operation" }>;
type BlobMap = Map<Digest, Uint8Array>;
export type SessionBrokerCoreApply = (command: CoreCommand, finalize:
  (state: SessionAggregateState, outcome: StoredSessionCommandOutcome, blobs: BlobMap) => Promise<void>) => Promise<ApplySessionCommandResult>;

const receiptKinds: SessionBrokerReceiptKind[] = ["acquire", "commit", "retry", "claim", "dispatch", "confirmation", "settlement", "recovery_settlement", "block"];
const kindForOperation = {
  "acquire-step": "acquire", "commit-step": "commit", "prepare-retry": "retry", "claim-start": "claim",
  dispatch: "dispatch", confirm: "confirmation", settle: "settlement", block: "block", "settle-recovery": "recovery_settlement",
} as const;

function same(a: unknown, b: unknown): boolean {
  const left = encodeCanonicalCbor(a as NormalizedValue);
  const right = encodeCanonicalCbor(b as NormalizedValue);
  return left.byteLength === right.byteLength && left.every((byte, index) => byte === right[index]);
}
function emptyBroker(): SessionBrokerState {
  return { receiptSequence: 0, receiptsThrough: 0, receipts: [], engineGrant: null, preparation: null, dispatch: null, start: null };
}
function fence(state: SessionAggregateState): SessionFence {
  return { turnLeaseGeneration: state.activeTurn?.turnLeaseGeneration ?? 0,
    placementGeneration: state.placementGeneration, sandboxGeneration: state.sandboxGeneration,
    authorizationGeneration: state.authorizationGeneration };
}
function activeEffect(state: SessionAggregateState): SessionEffect | null {
  return state.effects.find((effect) => effect.effectId === state.activeTurn?.activeEffectId) ?? null;
}
async function chainDigest(state: SessionAggregateState): Promise<Digest> {
  const turn = state.activeTurn;
  if (turn === null) sessionError("NOT_FOUND", "Session has no active turn");
  if (turn.checkpointChainDigest !== undefined) return turn.checkpointChainDigest;
  if (!("payloadBytes" in turn.checkpoint)) sessionError("FAILED_PRECONDITION", "external checkpoint lacks its chain digest");
  return checkpointDigest(turn.checkpoint);
}
function scope(state: SessionAggregateState) {
  if (state.activeTurn === null) sessionError("NOT_FOUND", "Session has no active turn");
  return { tenantId: state.tenantId, workspaceId: state.workspaceId, userId: state.userId,
    sessionId: state.sessionId, turnId: state.activeTurn.turnId };
}
function key(effect: SessionBrokerEffectKey): SessionBrokerEffectKey {
  return { turnId: effect.turnId, effectId: effect.effectId, invocationId: effect.invocationId, requestDigest: effect.requestDigest };
}
function effectSnapshot(effect: SessionEffect | null): SessionBrokerSnapshot["activeEffect"] {
  return effect === null ? null : { effectId: effect.effectId, invocationId: effect.invocationId,
    requestDigest: effect.requestDigest, phase: effect.phase, dispatchAttempt: effect.dispatchAttempt };
}
function assertKey(state: SessionAggregateState, expected: SessionBrokerEffectKey): SessionEffect {
  const effect = activeEffect(state);
  if (effect === null || !same(key(effect), expected)) sessionError("NOT_FOUND", "broker effect identity is not active");
  return effect;
}
async function assertSnapshot(state: SessionAggregateState, snapshot: SessionBrokerSnapshot, sequence = state.eventSequence): Promise<void> {
  if (state.activeTurn === null || state.activeTurn.turnId !== snapshot.turnId) sessionError("NOT_FOUND", "broker turn is not active");
  if (!same(snapshot.fence, fence(state))) sessionError("STALE_GENERATION", "broker snapshot fence is stale");
  if (snapshot.eventSequence !== sequence || snapshot.checkpointDigest !== await chainDigest(state) ||
    !same(snapshot.activeEffect, effectSnapshot(activeEffect(state)))) {
    sessionError("CONFLICT", "broker snapshot does not match the authoritative Session state");
  }
}
function assertLive(state: SessionAggregateState, now: number, allowAbort = false): void {
  if (state.activeTurn === null) sessionError("NOT_FOUND", "Session has no active turn");
  if (now >= state.activeTurn.leaseExpiresAt) sessionError("FAILED_PRECONDITION", "turn lease has expired");
  if (!allowAbort && state.activeTurn.abortRequested) sessionError("FAILED_PRECONDITION", "turn abort blocks new work");
}
function assertNoStart(effect: SessionEffect): void {
  if (effect.lastDispatch?.start !== null && effect.lastDispatch?.start !== undefined) {
    sessionError("DISPATCH_ALREADY_STARTED", "dispatch attempt already has a durable start claim");
  }
}

export async function sessionBrokerOperationIdentity(request: SessionBrokerMutation): Promise<{
  kind: SessionBrokerReceiptKind; operationKey: string; operationKeyDigest: Digest;
}> {
  const operationKey = request.operation === "claim-start"
    ? await digestStructuredValue("circulusd.session.broker.dispatch-start-key", 1, {
      key: request.body.key, dispatchOpaque: request.body.dispatchOpaque,
    }) : request.body.operationKey;
  return { kind: kindForOperation[request.operation], operationKey,
    operationKeyDigest: await digestStructuredValue("circulusd.session.broker.operation-key", 1, operationKey) };
}

export function assertSessionBrokerReceipt(receipt: SessionBrokerStoredReceipt): void {
  brokerExact(receipt, ["sequence", "kind", "operationKey", "operationKeyDigest", "operationDigest", "requestDigest", "resultPayloadRef", "referencedBlobs"], "broker receipt");
  brokerInteger(receipt.sequence, "receipt.sequence", 1);
  if (!receiptKinds.includes(receipt.kind)) sessionError("FAILED_PRECONDITION", "unknown stored broker receipt kind");
  brokerIdentifier(receipt.operationKey, "receipt.operationKey");
  parseDigest(receipt.operationKeyDigest); parseDigest(receipt.operationDigest); parseDigest(receipt.requestDigest);
  validateSessionPayloadRef(receipt.resultPayloadRef, "broker receipt result");
  if (!Array.isArray(receipt.referencedBlobs) || receipt.referencedBlobs.length > 8) sessionError("FAILED_PRECONDITION", "broker receipt payload references exceed their bound");
  for (const reference of receipt.referencedBlobs) {
    brokerExact(reference, ["digest", "encodedBytes"], "broker payload reference");
    parseDigest(reference.digest); brokerInteger(reference.encodedBytes, "encodedBytes", 1);
    if (reference.encodedBytes > 4 * 1_048_576) sessionError("FAILED_PRECONDITION", "broker payload reference exceeds blob limit");
  }
}

const scopeFields = ["tenantId", "workspaceId", "userId", "sessionId", "turnId"];
const preparationFields = [...scopeFields, "effectId", "invocationId", "requestDigest", "opaque", "service", "operation",
  "parentOperationId", "ordinal", "replayPolicy", "fence", "dispatchAttempt", "deadline", "eventSequence", "durable"];
function assertPermit(value: SessionBrokerPreparationPermit | SessionBrokerDispatchPermit, dispatch = false): void {
  brokerExact(value, [...preparationFields, ...(dispatch ? ["providerRequestId", "providerRouteDigest"] : [])], "broker effect permit");
  for (const field of [...scopeFields, "effectId", "invocationId", "operation"] as const) {
    brokerIdentifier((value as unknown as Record<string, unknown>)[field], `permit.${field}`);
  }
  if (value.parentOperationId !== null) brokerIdentifier(value.parentOperationId, "parentOperationId");
  brokerInteger(value.ordinal, "ordinal"); brokerInteger(value.dispatchAttempt, "dispatchAttempt", 1);
  brokerInteger(value.deadline, "deadline", 1); brokerInteger(value.eventSequence, "eventSequence", 1);
  brokerOpaque(value.opaque, "permit opaque"); brokerFence(value.fence); parseDigest(value.requestDigest);
  if (value.durable !== true) sessionError("FAILED_PRECONDITION", "stored effect permit lacks its durability marker");
  if (dispatch) {
    const permit = value as SessionBrokerDispatchPermit;
    if (permit.providerRequestId !== null) brokerIdentifier(permit.providerRequestId, "providerRequestId");
    parseDigest(permit.providerRouteDigest);
  }
}

export function assertSessionBrokerState(state: SessionAggregateState): void {
  const broker = state.broker;
  if (broker === undefined) return;
  brokerExact(broker, ["receiptSequence", "receiptsThrough", "receipts", "engineGrant", "preparation", "dispatch", "start"], "broker state");
  brokerInteger(broker.receiptSequence, "broker.receiptSequence"); brokerInteger(broker.receiptsThrough, "broker.receiptsThrough");
  if (!Array.isArray(broker.receipts) || broker.receiptSequence - broker.receiptsThrough !== broker.receipts.length ||
    (broker.receiptsThrough > 0 && state.history === undefined)) sessionError("FAILED_PRECONDITION", "broker receipt archive watermark is invalid");
  const keys = new Set<string>();
  for (const [index, receipt] of broker.receipts.entries()) {
    assertSessionBrokerReceipt(receipt);
    const identity = `${receipt.kind}:${receipt.operationKeyDigest}`;
    if (keys.has(identity) || receipt.sequence !== broker.receiptsThrough + index + 1) sessionError("FAILED_PRECONDITION", "broker receipts must be unique and contiguous");
    keys.add(identity);
  }
  const grant = broker.engineGrant;
  if (grant !== null) {
    brokerExact(grant, [...scopeFields, "opaque", "operationKey", "fence", "expectedEventSequence", "checkpointDigest", "budget", "deadline", "checkpoint", "unconsumedSettlement", "durable"], "engine grant");
    brokerIdentifier(grant.operationKey, "grant.operationKey");
    brokerInteger(grant.deadline, "grant.deadline", 1); brokerInteger(grant.expectedEventSequence, "grant.expectedEventSequence");
    parseDigest(grant.checkpointDigest);
    brokerExact(grant.budget, ["maximumEvents", "maximumEphemeralBytes", "maximumWallClockMs"], "grant budget");
    brokerInteger(grant.budget.maximumEphemeralBytes, "maximumEphemeralBytes", 1);
    brokerInteger(grant.budget.maximumWallClockMs, "maximumWallClockMs", 1);
    if (grant.budget.maximumEvents !== 1) sessionError("FAILED_PRECONDITION", "engine grant must authorize one boundary");
    if ("payloadBytes" in grant.checkpoint) parseAgentCheckpoint(grant.checkpoint);
    else parseExternalizedAgentCheckpoint(grant.checkpoint);
    const currentCheckpoint = state.activeTurn?.checkpoint;
    if (currentCheckpoint === undefined || grant.checkpoint.sessionId !== state.sessionId || grant.checkpoint.turnId !== grant.turnId ||
      ("payloadSize" in currentCheckpoint && !same(grant.checkpoint, currentCheckpoint)) ||
      (state.activeTurn?.checkpointChainDigest !== undefined && grant.checkpointDigest !== state.activeTurn.checkpointChainDigest)) {
      sessionError("FAILED_PRECONDITION", "engine grant checkpoint is not current");
    }
    if (grant.unconsumedSettlement !== null) {
      brokerExact(grant.unconsumedSettlement, ["effect", "settlement"], "grant settlement");
      const current = activeEffect(state);
      if (current?.phase !== "settled" || grant.unconsumedSettlement.effect.effectId !== current.effectId ||
        !same(grant.unconsumedSettlement.effect.settlement, grant.unconsumedSettlement.settlement)) {
        sessionError("FAILED_PRECONDITION", "engine grant settlement is not the unconsumed effect");
      }
    } else if (activeEffect(state)?.phase === "settled") sessionError("FAILED_PRECONDITION", "engine grant omitted its unconsumed settlement");
    brokerOpaque(grant.opaque, "grant opaque"); brokerFence(grant.fence);
    if (grant.durable !== true || grant.tenantId !== state.tenantId || grant.workspaceId !== state.workspaceId ||
      grant.userId !== state.userId || grant.sessionId !== state.sessionId || grant.turnId !== state.activeTurn?.turnId ||
      grant.expectedEventSequence !== state.eventSequence || !same(grant.fence, fence(state))) {
      sessionError("FAILED_PRECONDITION", "active engine grant does not bind the current Session");
    }
  }
  if (broker.preparation !== null) assertPermit(broker.preparation.permit);
  if (broker.dispatch !== null) assertPermit(broker.dispatch, true);
  if (broker.start !== null) {
    brokerExact(broker.start, ["dispatch", "opaque", "commandDigest", "eventSequence", "durable"], "dispatch start permit");
    assertPermit(broker.start.dispatch, true); brokerOpaque(broker.start.opaque, "start opaque"); parseDigest(broker.start.commandDigest);
    brokerInteger(broker.start.eventSequence, "start.eventSequence", 1);
    if (broker.start.durable !== true) sessionError("FAILED_PRECONDITION", "dispatch start lacks its durability marker");
  }
  for (const permit of [broker.preparation?.permit, broker.dispatch, broker.start?.dispatch]) {
    if (permit === null || permit === undefined) continue;
    brokerOpaque(permit.opaque, "effect permit opaque"); brokerFence(permit.fence);
    const effect = activeEffect(state);
    if (effect === null || permit.durable !== true || !same(key(permit), key(effect)) ||
      permit.tenantId !== state.tenantId || permit.workspaceId !== state.workspaceId || permit.userId !== state.userId ||
      permit.sessionId !== state.sessionId || permit.service !== effect.service || permit.operation !== effect.operation ||
      permit.replayPolicy !== effect.replayPolicy || permit.parentOperationId !== (effect.parentOperationId ?? null) ||
      permit.ordinal !== (effect.ordinal ?? 0)) sessionError("FAILED_PRECONDITION", "broker effect permit is not bound to its effect");
  }
  if (broker.preparation !== null) {
    const preparation = broker.preparation;
    brokerExact(preparation, ["permit", "sourceEventSequence", "sourceDispatchAttempt", "sourceCheckpointDigest", "retry"], "effect preparation");
    brokerInteger(preparation.sourceEventSequence, "sourceEventSequence"); brokerInteger(preparation.sourceDispatchAttempt, "sourceDispatchAttempt");
    parseDigest(preparation.sourceCheckpointDigest);
    const effect = activeEffect(state)!;
    if (typeof preparation.retry !== "boolean" || preparation.permit.dispatchAttempt !== effect.dispatchAttempt + 1 ||
      preparation.sourceDispatchAttempt !== effect.dispatchAttempt ||
      preparation.permit.eventSequence > state.eventSequence ||
      (preparation.retry && preparation.permit.eventSequence !== preparation.sourceEventSequence + 1) ||
      (!preparation.retry && effect.phase !== "prepared")) sessionError("FAILED_PRECONDITION", "effect preparation reservation is inconsistent");
  }
  if (broker.dispatch !== null && broker.dispatch.dispatchAttempt !== activeEffect(state)?.dispatchAttempt) {
    sessionError("FAILED_PRECONDITION", "broker dispatch attempt is inconsistent");
  }
  if (broker.start !== null && (!same(broker.start.dispatch, broker.dispatch) ||
    broker.start.eventSequence !== activeEffect(state)?.lastDispatch?.start?.claimedEventSequence)) {
    sessionError("FAILED_PRECONDITION", "broker dispatch start proof is inconsistent");
  }
}

export function reconcileSessionBrokerState(state: SessionAggregateState): void {
  const broker = state.broker;
  if (broker === undefined) return;
  if (broker.engineGrant !== null && (broker.engineGrant.turnId !== state.activeTurn?.turnId ||
    broker.engineGrant.expectedEventSequence !== state.eventSequence || !same(broker.engineGrant.fence, fence(state)))) broker.engineGrant = null;
  const effect = activeEffect(state);
  if (effect === null || effect.phase === "settled") {
    broker.preparation = null; broker.dispatch = null; broker.start = null;
  } else {
    if (broker.preparation !== null && (broker.preparation.permit.effectId !== effect.effectId ||
      broker.preparation.sourceDispatchAttempt !== effect.dispatchAttempt || !same(broker.preparation.permit.fence, fence(state)))) broker.preparation = null;
    if (broker.dispatch !== null && (broker.dispatch.effectId !== effect.effectId || broker.dispatch.dispatchAttempt !== effect.dispatchAttempt)) {
      broker.dispatch = null; broker.start = null;
    }
  }
}

function payloadReferences(value: unknown): Array<{ digest: Digest; encodedBytes: number }> {
  const references = new Map<Digest, number>();
  const visit = (node: unknown): void => {
    if (node === null || typeof node !== "object" || node instanceof Uint8Array) return;
    if (Array.isArray(node)) { for (const entry of node) visit(entry); return; }
    const record = node as Record<string, unknown>;
    if (record.encoding === "canonical-cbor-v1" && typeof record.digest === "string" && typeof record.encodedBytes === "number") {
      references.set(parseDigest(record.digest), record.encodedBytes);
    } else if (typeof record.payloadEncoding === "string" && typeof record.payloadDigest === "string" && typeof record.payloadSize === "number") {
      references.set(parseDigest(record.payloadDigest), record.payloadSize);
    }
    for (const entry of Object.values(record)) visit(entry);
  };
  visit(value);
  return [...references].map(([digest, encodedBytes]) => ({ digest, encodedBytes }));
}
export function sessionBrokerBlobReferences(state: SessionAggregateState): Array<{ digest: Digest; encodedBytes: number }> {
  const broker = state.broker;
  if (broker === undefined) return [];
  return [...broker.receipts.flatMap((receipt) => [{ digest: receipt.resultPayloadRef.digest, encodedBytes: receipt.resultPayloadRef.encodedBytes }, ...receipt.referencedBlobs]),
    ...payloadReferences(broker.engineGrant)];
}

async function storedCheckpoint(checkpoint: StoredSessionCheckpoint, blobs: BlobMap): Promise<StoredSessionCheckpoint> {
  if (!("payloadBytes" in checkpoint)) return structuredClone(checkpoint);
  const external = externalizeAgentCheckpoint(checkpoint);
  blobs.set(checkpoint.payloadDigest, checkpoint.payloadBytes.slice());
  return external.checkpoint;
}
async function storedEffect(effect: SessionEffect, blobs: BlobMap): Promise<SessionEffect> {
  let result = structuredClone(effect);
  if (result.requestPayloadRef === undefined) {
    const { requestPayload, ...metadata } = result;
    result = { ...metadata, requestPayloadRef: await storeSessionPayload(requestPayload, blobs) };
  }
  if (result.settlement?.kind === "success" && result.settlement.resultPayloadRef === undefined) {
    result.settlement = { kind: "success", resultPayloadRef: await storeSessionPayload(result.settlement.result, blobs) };
  }
  return result;
}

export async function readSessionBrokerTurn(state: SessionAggregateState, policy: SessionBrokerPolicy): Promise<SessionBrokerTurn> {
  const effect = activeEffect(state);
  return { tenantId: state.tenantId, workspaceId: state.workspaceId, userId: state.userId, sessionId: state.sessionId,
    turnId: state.activeTurn?.turnId ?? null, active: state.activeTurn !== null,
    abortRequested: state.activeTurn?.abortRequested ?? false, leaseExpiresAt: state.activeTurn?.leaseExpiresAt ?? null,
    fence: fence(state), eventSequence: state.eventSequence, engineStepLimits: structuredClone(policy.engineStepLimits),
    checkpointDigest: state.activeTurn === null ? null : await chainDigest(state), checkpoint: state.activeTurn?.checkpoint ?? null,
    activeEffect: effect, preparation: state.broker?.preparation?.permit ?? null, dispatch: state.broker?.dispatch ?? null,
    start: state.broker?.start ?? null,
    unconsumedSettlement: effect?.settlement === null || effect?.settlement === undefined ? null :
      { effect: structuredClone(effect), settlement: structuredClone(effect.settlement) } };
}

export async function materializeSessionBrokerReceipt(receipt: SessionBrokerStoredReceipt,
  readBlob: (digest: Digest) => Promise<Uint8Array | undefined>, replayedClaim = false): Promise<SessionBrokerReceiptValue> {
  assertSessionBrokerReceipt(receipt);
  const value = await readSessionPayload(receipt.resultPayloadRef, readBlob);
  if (value === null || typeof value !== "object" || Array.isArray(value) || value instanceof Uint8Array) {
    sessionError("FAILED_PRECONDITION", "stored broker receipt is not an object");
  }
  const result = value as unknown as SessionBrokerReceiptValue;
  if (receipt.kind === "claim" && replayedClaim) return { ...result, fresh: false } as SessionBrokerReceiptValue;
  return result;
}

export async function sessionBrokerLookupResult(lookup: SessionBrokerOperationLookup, receipt: SessionBrokerStoredReceipt | null,
  readBlob: (digest: Digest) => Promise<Uint8Array | undefined>): Promise<SessionBrokerOperationReceipt> {
  if (receipt === null) return { found: false, kind: lookup.kind, operationDigest: lookup.operationDigest, receipt: null };
  assertSessionBrokerReceipt(receipt);
  if (receipt.kind !== lookup.kind || receipt.operationKey !== lookup.operationKey) sessionError("FAILED_PRECONDITION", "broker receipt identity does not match lookup");
  if (receipt.operationDigest !== lookup.operationDigest) sessionError("IDEMPOTENCY_CONFLICT", "broker operation key was reused with another digest");
  return { found: true, kind: lookup.kind, operationDigest: receipt.operationDigest,
    receipt: await materializeSessionBrokerReceipt(receipt, readBlob) as NonNullable<SessionBrokerOperationReceipt["receipt"]> };
}

function newPreparation(state: SessionAggregateState, effect: SessionEffect, opaque: Uint8Array, deadline: number,
  eventSequence: number): SessionBrokerPreparationPermit {
  return { ...scope(state), ...key(effect), opaque: opaque.slice(), service: effect.service, operation: effect.operation,
    parentOperationId: effect.parentOperationId ?? null, ordinal: effect.ordinal ?? 0, replayPolicy: effect.replayPolicy,
    fence: fence(state), dispatchAttempt: effect.dispatchAttempt + 1, deadline, eventSequence, durable: true };
}

async function appendReceipt(state: SessionAggregateState, identity: Awaited<ReturnType<typeof sessionBrokerOperationIdentity>>,
  operationDigest: Digest, requestDigest: Digest, result: SessionBrokerReceiptValue, blobs: BlobMap): Promise<SessionBrokerStoredReceipt> {
  const broker = state.broker ??= emptyBroker();
  if (broker.receiptSequence === Number.MAX_SAFE_INTEGER) sessionError("FAILED_PRECONDITION", "broker receipt sequence exhausted");
  const receipt: SessionBrokerStoredReceipt = { ...identity, sequence: ++broker.receiptSequence, operationDigest, requestDigest,
    resultPayloadRef: await storeSessionPayload(result as unknown as NormalizedValue, blobs), referencedBlobs: payloadReferences(result) };
  assertSessionBrokerReceipt(receipt);
  broker.receipts.push(receipt);
  return receipt;
}

async function finish(previous: SessionAggregateState, state: SessionAggregateState, command: SessionBrokerCommand,
  commandDigest: Digest, receipt: SessionBrokerStoredReceipt, blobs: BlobMap, context: SessionApplyContext,
  boundary?: "retry" | "block" | "recovery_settlement"): Promise<ApplySessionCommandResult> {
  if (boundary !== undefined) {
    state.eventSequence += 1;
    state.commandReceipts.push({ commandId: command.commandId, commandDigest, committedEventSequence: state.eventSequence,
      outcome: { kind: "broker_boundary", operation: boundary, effectId: (command.body as { key: SessionBrokerEffectKey }).key.effectId } });
  }
  reconcileSessionBrokerState(state);
  const compacted = context.history === undefined ? null : compactSessionHistory(state, context.historyMaxRecords);
  const next = compacted?.state ?? state;
  await validateSessionState(next);
  assertSessionCapacity(previous, next);
  return { state: next, outcome: { kind: "broker_result", receipt, replayedClaim: false }, commandDigest, replayed: false,
    blobs, referencedBlobs: sessionReferencedBlobDigests(next), ...(compacted === null ? {} : { archiveDelta: compacted.archive }) };
}

export async function applySessionBrokerCommand(state: SessionAggregateState, command: SessionBrokerCommand,
  context: SessionApplyContext | undefined, applyCore: SessionBrokerCoreApply): Promise<ApplySessionCommandResult> {
  await validateSessionState(state);
  assertSessionBrokerAuthority(state, command.authority);
  validateSessionBrokerCommandShape(command);
  const request = parseSessionBrokerRequest({ operation: command.operation, body: command.body });
  if (request.operation === "read-turn" || request.operation === "lookup-operation") sessionError("INVALID_ARGUMENT", "broker query is not a mutation");
  const policy = parseSessionBrokerPolicy(command.host.policy);
  if (context === undefined) sessionError("FAILED_PRECONDITION", "broker mutation requires trusted transaction context");
  const now = context.transactionTime;
  brokerInteger(now, "transactionTime");
  const identity = await sessionBrokerOperationIdentity(request);
  if (identity.operationKey !== command.operationKey || identity.operationKeyDigest !== command.operationKeyDigest) sessionError("INVALID_ARGUMENT", "broker operation key digest mismatch");
  const semantic = { ...request.body } as Record<string, unknown>;
  delete semantic.nowUnixMs;
  if (request.operation !== "acquire-step") delete semantic.snapshot;
  const requestDigest = await digestStructuredValue("circulusd.session.broker.request", 1, { operation: request.operation, body: semantic });
  const operationDigest = "operationDigest" in request.body ? request.body.operationDigest :
    request.operation === "commit-step" ? request.body.requestDigest : requestDigest;
  let original = state.broker?.receipts.find((receipt) => receipt.kind === identity.kind && receipt.operationKeyDigest === identity.operationKeyDigest);
  if (original === undefined) {
    const witness = context.history?.brokerOperation;
    if (witness !== undefined && (witness.kind !== identity.kind || witness.operationKey !== identity.operationKey || witness.operationKeyDigest !== identity.operationKeyDigest)) {
      sessionError("FAILED_PRECONDITION", "broker history witness has another identity");
    }
    if (witness === undefined && state.history !== undefined) sessionError("FAILED_PRECONDITION", "broker mutation lacks authenticated receipt lookup");
    original = witness?.receipt ?? undefined;
  }
  if (original !== undefined) {
    assertSessionBrokerReceipt(original);
    if (original.operationKey !== identity.operationKey || original.kind !== identity.kind) sessionError("FAILED_PRECONDITION", "broker receipt key binding is invalid");
    if (original.operationDigest !== operationDigest || original.requestDigest !== requestDigest) sessionError("IDEMPOTENCY_CONFLICT", "broker operation key was reused with another request");
    return { state, outcome: { kind: "broker_result", receipt: original, replayedClaim: identity.kind === "claim" }, commandDigest: requestDigest, replayed: true };
  }
  const reservation = state.broker?.preparation;
  const dispatchReservation = request.operation === "dispatch" && reservation?.retry === true ? reservation : null;
  await assertSnapshot(state, request.body.snapshot, dispatchReservation?.sourceEventSequence);
  if (command.expectedEventSequence !== request.body.snapshot.eventSequence) sessionError("INVALID_ARGUMENT", "broker command snapshot sequence mismatch");
  if (dispatchReservation !== null && (state.eventSequence !== dispatchReservation.permit.eventSequence ||
    dispatchReservation.sourceCheckpointDigest !== request.body.snapshot.checkpointDigest)) sessionError("CONFLICT", "retry preparation was superseded before dispatch");
  if (reservation?.retry === true && request.operation !== "dispatch" && request.operation !== "confirm" &&
    request.operation !== "block" && request.operation !== "settle-recovery" &&
    !(request.operation === "prepare-retry" && reservation.permit.deadline <= now)) {
    sessionError("FAILED_PRECONDITION", "durable retry reservation excludes other mutations");
  }
  const next = structuredClone(state);
  const broker = next.broker ??= emptyBroker();
  const blobs: BlobMap = new Map();
  let core: CoreCommand | undefined;
  let result: SessionBrokerReceiptValue | undefined;
  let finalReceipt: SessionBrokerStoredReceipt | undefined;
  const common = { commandId: command.commandId, expectedEventSequence: state.eventSequence,
    turnId: request.body.snapshot.turnId, fence: request.body.snapshot.fence };
  const coreTime = { transactionTime: now };
  let finalize: ((candidate: SessionAggregateState, ingested: BlobMap) => Promise<SessionBrokerReceiptValue>) | undefined;

  switch (request.operation) {
    case "acquire-step": {
      assertLive(state, now);
      if (activeEffect(state)?.phase !== undefined && activeEffect(state)?.phase !== "settled") sessionError("FAILED_PRECONDITION", "engine step has an outstanding effect");
      if (broker.engineGrant !== null && broker.engineGrant.deadline > now) sessionError("FAILED_PRECONDITION", "an engine grant is already outstanding");
      const { budget, nowUnixMs } = request.body;
      if (budget.maximumEvents !== 1 || budget.maximumEphemeralBytes > policy.engineStepLimits.maximumEphemeralBytes ||
        budget.maximumWallClockMs > policy.engineStepLimits.maximumWallClockMs) sessionError("FAILED_PRECONDITION", "engine budget exceeds trusted runtime policy");
      const deadline = nowUnixMs + budget.maximumWallClockMs;
      brokerInteger(deadline, "grant deadline", 1);
      if (nowUnixMs > now || deadline <= now || deadline > state.activeTurn!.leaseExpiresAt) sessionError("FAILED_PRECONDITION", "engine grant deadline is invalid or expired");
      const effect = activeEffect(state);
      const grantEffect = effect === null ? null : await storedEffect(effect, blobs);
      const grant: SessionBrokerEngineGrant = { ...scope(state), opaque: command.host.opaque.slice(), operationKey: request.body.operationKey,
        fence: fence(state), expectedEventSequence: state.eventSequence, checkpointDigest: await chainDigest(state),
        budget: structuredClone(budget), deadline, checkpoint: await storedCheckpoint(state.activeTurn!.checkpoint, blobs),
        unconsumedSettlement: grantEffect?.settlement === null || grantEffect?.settlement === undefined ? null :
          { effect: grantEffect, settlement: structuredClone(grantEffect.settlement) }, durable: true };
      broker.engineGrant = grant;
      const receipt = await appendReceipt(next, identity, operationDigest, requestDigest, grant, blobs);
      return finish(state, next, command, requestDigest, receipt, blobs, context);
    }
    case "commit-step": {
      assertLive(state, now);
      const grant = broker.engineGrant;
      if (grant === null || !same(grant.opaque, request.body.permitOpaque) || grant.deadline <= now ||
        request.body.nowUnixMs > now || request.body.nowUnixMs >= grant.deadline ||
        grant.expectedEventSequence !== state.eventSequence || grant.checkpointDigest !== await chainDigest(state)) sessionError("FAILED_PRECONDITION", "engine grant is absent, expired or consumed");
      core = { ...common, ...coreTime, kind: "commit_engine_step", step: request.body.step,
        consumedSettlementEffectId: grant.unconsumedSettlement?.effect.effectId ?? null,
        effectIdentity: request.body.step.kind === "effect_request" ? { effectId: command.host.effectId, invocationId: command.host.invocationId } : null };
      finalize = async (candidate, ingested) => {
        const metadata = candidate.broker ??= emptyBroker();
        metadata.engineGrant = null;
        const effect = activeEffect(candidate);
        let preparation: SessionBrokerPreparationPermit | null = null;
        if (effect !== null && effect.phase === "prepared") {
          const deadline = Math.min(candidate.activeTurn!.leaseExpiresAt, now + policy.preparationTTLms);
          brokerInteger(deadline, "preparation deadline", 1);
          preparation = newPreparation(candidate, effect, command.host.secondaryOpaque, deadline, candidate.eventSequence);
          metadata.preparation = { permit: preparation, sourceEventSequence: candidate.eventSequence,
            sourceDispatchAttempt: 0, sourceCheckpointDigest: await chainDigest(candidate), retry: false };
        }
        return { operationKey: request.body.operationKey, eventSequence: candidate.eventSequence, durable: true,
          preparedEffect: effect === null ? null : await storedEffect(effect, ingested), preparation };
      };
      break;
    }
    case "dispatch": {
      assertLive(state, now);
      const effect = assertKey(state, request.body.key);
      const preparation = broker.preparation;
      if (preparation === null || !same(preparation.permit.opaque, request.body.preparationOpaque) ||
        preparation.permit.deadline !== request.body.deadlineUnixMs || preparation.permit.deadline <= now ||
        request.body.nowUnixMs > now || !same(preparation.permit.fence, fence(state))) sessionError("FAILED_PRECONDITION", "dispatch lacks its exact live preparation");
      if (preparation.retry) {
        assertNoStart(effect);
        core = effect.phase === "blocked" ? { ...common, ...coreTime, ...request.body.key, kind: "resolve_confirmation", decision: "retry",
          deadline: request.body.deadlineUnixMs, providerRequestId: request.body.providerRequestId, providerRouteDigest: request.body.providerRouteDigest } :
          { ...common, ...coreTime, ...request.body.key, kind: "recover_effect", deadline: request.body.deadlineUnixMs,
            providerRequestId: request.body.providerRequestId, providerRouteDigest: request.body.providerRouteDigest };
      } else {
        core = { ...common, ...coreTime, ...request.body.key, kind: "dispatch_effect", deadline: request.body.deadlineUnixMs,
          providerRequestId: request.body.providerRequestId, providerRouteDigest: request.body.providerRouteDigest };
      }
      finalize = async (candidate) => {
        const current = activeEffect(candidate)!;
        const permit: SessionBrokerDispatchPermit = { ...preparation.permit, opaque: command.host.opaque.slice(),
          dispatchAttempt: current.dispatchAttempt, eventSequence: candidate.eventSequence,
          providerRequestId: request.body.providerRequestId, providerRouteDigest: request.body.providerRouteDigest };
        candidate.broker!.preparation = null; candidate.broker!.dispatch = permit; candidate.broker!.start = null;
        return permit;
      };
      break;
    }
    case "claim-start": {
      assertLive(state, now);
      const effect = assertKey(state, request.body.key);
      const dispatch = broker.dispatch;
      if (dispatch === null || !same(dispatch.opaque, request.body.dispatchOpaque) || dispatch.deadline <= now ||
        request.body.nowUnixMs > now || !same(dispatch.fence, fence(state))) sessionError("FAILED_PRECONDITION", "start claim lacks its exact live dispatch proof");
      if (broker.start !== null) sessionError("IDEMPOTENCY_CONFLICT", "dispatch start already has a different command binding");
      const claims = parseDispatchPermitClaims({ tenantId: state.tenantId, userId: state.userId, sessionId: state.sessionId, ...key(effect),
        service: effect.service, operation: effect.operation, replayPolicy: effect.replayPolicy,
        ...(effect.parentOperationId === undefined ? {} : { parentOperationId: effect.parentOperationId, ordinal: effect.ordinal }),
        dispatchAttempt: dispatch.dispatchAttempt, ...dispatch.fence, providerRouteDigest: dispatch.providerRouteDigest, deadline: dispatch.deadline });
      core = { ...common, ...coreTime, ...request.body.key, kind: "claim_dispatch_start", expectedEventSequence: dispatch.eventSequence,
        workspaceId: state.workspaceId, dispatchAttempt: dispatch.dispatchAttempt, providerRequestId: dispatch.providerRequestId,
        providerRouteDigest: dispatch.providerRouteDigest, dispatchPermitClaims: claims, commandDigest: request.body.commandDigest };
      finalize = async (candidate) => {
        const permit = { dispatch, opaque: command.host.opaque.slice(), commandDigest: request.body.commandDigest,
          eventSequence: candidate.eventSequence, durable: true as const };
        candidate.broker!.start = permit;
        return { fresh: true, permit };
      };
      break;
    }
    case "confirm": {
      const effect = assertKey(state, request.body.key);
      const dispatch = effect.lastDispatch;
      if (dispatch === null || dispatch.dispatchAttempt !== request.body.dispatchAttempt ||
        dispatch.providerRequestId !== request.body.providerRequestId || dispatch.providerRouteDigest !== request.body.providerRouteDigest) sessionError("CONFLICT", "external commit provider identity does not match dispatch");
      core = { ...common, ...request.body.key, kind: "record_external_commit", dispatchAttempt: request.body.dispatchAttempt,
        externalCommitId: request.body.externalCommitId, resultRef: request.body.resultRef };
      finalize = async (candidate) => {
        candidate.broker!.preparation = null;
        return { ...scope(candidate), ...request.body.key, service: effect.service, operation: effect.operation,
          dispatchAttempt: request.body.dispatchAttempt, providerRequestId: request.body.providerRequestId,
          externalCommitId: request.body.externalCommitId, resultRef: request.body.resultRef, operationDigest,
          eventSequence: candidate.eventSequence, durable: true };
      };
      break;
    }
    case "settle": {
      const effect = assertKey(state, request.body.key);
      if (effect.phase !== "externally_committed" || effect.externalCommitId !== request.body.externalCommitId ||
        effect.resultRef !== request.body.resultRef || effect.dispatchAttempt !== request.body.dispatchAttempt) sessionError("FAILED_PRECONDITION", "settlement lacks the exact external commit proof");
      if ((request.body.error === null) !== (request.body.settlement.kind === "success") ||
        (request.body.error === null && request.body.resultRef === null)) sessionError("INVALID_ARGUMENT", "settlement outcome does not match its result/error proof");
      // Keep the full PublicError in the original receipt while only the fixed,
      // bounded engine-facing projection enters Pi state. This matches the Go
      // Store and does not copy arbitrarily large provider diagnostics to Pi.
      if (request.body.error !== null && (request.body.settlement.kind !== "error" ||
        request.body.settlement.code !== "effect.failed" || request.body.settlement.message !== "The effect failed." ||
        request.body.settlement.retryable !== request.body.error.retryable)) sessionError("INVALID_ARGUMENT", "settlement error body does not match its public error");
      core = { ...common, ...request.body.key, kind: "settle_effect", dispatchAttempt: request.body.dispatchAttempt, settlement: request.body.settlement };
      finalize = async (candidate, ingested) => settlementReceipt(candidate, request.body.key, operationDigest, request.body.error, null, ingested);
      break;
    }
    case "prepare-retry": {
      assertLive(state, now);
      const effect = assertKey(next, request.body.key);
      assertNoStart(effect);
      if (request.body.nowUnixMs > now || request.body.deadlineUnixMs <= now || request.body.deadlineUnixMs > next.activeTurn!.leaseExpiresAt ||
        (effect.phase !== "dispatched" && effect.phase !== "blocked") ||
        (effect.replayPolicy !== "safe" && effect.replayPolicy !== "idempotency-key" &&
          !(effect.replayPolicy === "confirm" && effect.phase === "blocked" && request.body.userConfirmed))) sessionError("FAILED_PRECONDITION", "effect cannot reserve this retry");
      const permit = newPreparation(next, effect, command.host.opaque, request.body.deadlineUnixMs, next.eventSequence + 1);
      broker.preparation = { permit, sourceEventSequence: next.eventSequence, sourceDispatchAttempt: effect.dispatchAttempt,
        sourceCheckpointDigest: await chainDigest(next), retry: true };
      const receipt = await appendReceipt(next, identity, operationDigest, requestDigest, permit, blobs);
      return finish(state, next, command, requestDigest, receipt, blobs, context, "retry");
    }
    case "block": {
      const effect = assertKey(next, request.body.key);
      assertNoStart(effect);
      if (effect.phase !== "dispatched" || effect.replayPolicy !== "confirm") sessionError("FAILED_PRECONDITION", "only an uncertain confirm effect can block");
      effect.phase = "blocked"; next.activeTurn!.status = "needs_confirmation"; broker.preparation = null;
      appendBrokerPublicEvent(next, effect, "turn.needs_confirmation");
      result = { ...scope(next), ...key(effect), state: "blocked", replayPolicy: effect.replayPolicy, dispatchAttempt: effect.dispatchAttempt,
        operationDigest, reason: request.body.reason, eventSequence: next.eventSequence + 1, durable: true };
      const receipt = await appendReceipt(next, identity, operationDigest, requestDigest, result, blobs);
      return finish(state, next, command, requestDigest, receipt, blobs, context, "block");
    }
    case "settle-recovery": {
      const effect = assertKey(next, request.body.key);
      assertNoStart(effect);
      if (effect.phase !== "prepared" && effect.phase !== "dispatched") sessionError("FAILED_PRECONDITION", "effect cannot be settled by recovery");
      if (request.body.kind === "failed" && effect.phase !== "prepared") sessionError("FAILED_PRECONDITION", "failed recovery settlement is only valid before dispatch");
      if (request.body.kind === "interrupted_unknown" && effect.phase !== "dispatched") sessionError("FAILED_PRECONDITION", "interrupted recovery settlement requires an uncertain dispatch");
      effect.phase = "settled";
      effect.settlement = request.body.kind === "failed" ? { kind: "error", code: request.body.error.reason || `BROKER_ERROR_${request.body.error.code}`,
        message: request.body.error.message, retryable: request.body.error.retryable } :
        { kind: "interrupted_unknown", reason: request.body.error.reason || "uncertain dispatch interrupted" };
      appendBrokerPublicEvent(next, effect, effect.service === "model" ? "model.settled" : "tool.settled");
      result = await settlementReceipt(next, request.body.key, operationDigest, request.body.error, request.body.kind, blobs, next.eventSequence + 1);
      const receipt = await appendReceipt(next, identity, operationDigest, requestDigest, result, blobs);
      return finish(state, next, command, requestDigest, receipt, blobs, context, "recovery_settlement");
    }
  }
  if (core === undefined || finalize === undefined) sessionError("FAILED_PRECONDITION", "broker operation lacks its typed transition");
  const applied = await applyCore(core, async (candidate, _outcome, ingested) => {
    candidate.broker ??= emptyBroker();
    const value = await finalize(candidate, ingested);
    finalReceipt = await appendReceipt(candidate, identity, operationDigest, requestDigest, value, ingested);
  });
  if (finalReceipt === undefined) sessionError("FAILED_PRECONDITION", "broker transition did not commit its original receipt");
  return { ...applied, outcome: { kind: "broker_result", receipt: finalReceipt, replayedClaim: false } };
}

async function settlementReceipt(state: SessionAggregateState, effectKey: SessionBrokerEffectKey, operationDigest: Digest,
  error: SessionBrokerSettlementReceipt["error"], recoveryKind: SessionBrokerSettlementReceipt["recoveryKind"], blobs: BlobMap,
  eventSequence = state.eventSequence): Promise<SessionBrokerSettlementReceipt> {
  const effect = assertKey(state, effectKey);
  return { ...scope(state), ...effectKey, state: "settled", dispatchAttempt: effect.dispatchAttempt,
    externalCommitId: effect.externalCommitId, resultRef: effect.resultRef, error, operationDigest, recoveryKind,
    effect: await storedEffect(effect, blobs), eventSequence, durable: true };
}

function appendBrokerPublicEvent(state: SessionAggregateState, effect: SessionEffect,
  type: "turn.needs_confirmation" | "model.settled" | "tool.settled"): void {
  if (!state.turnAdmissionReceipts.some((receipt) => receipt.turnId === effect.turnId)) return;
  if (state.publicEventSequence === Number.MAX_SAFE_INTEGER) sessionError("FAILED_PRECONDITION", "public event sequence exhausted");
  state.publicEvents.push({ sequence: ++state.publicEventSequence, turnId: effect.turnId, turnSequence: state.activeTurn!.sequence,
    effectId: effect.effectId, invocationId: effect.invocationId, service: effect.service, operation: effect.operation,
    ...(type === "turn.needs_confirmation" ? { type } : { type, settlementKind: effect.settlement!.kind }) });
}
