import { isDigest, type Digest } from "@circulusd/protocol-types";

import { sessionError } from "./errors.ts";
import { assertSessionBrokerAuthority, validateSessionBrokerCommandShape } from "./broker-validation.ts";
import { SESSION_BROKER_HOT_RECEIPTS, type SessionBrokerReceiptKind } from "./broker-types.ts";
import {
  SESSION_HISTORY_HOT_COMMANDS, SESSION_HISTORY_HOT_PUBLIC_EVENTS,
  SESSION_HISTORY_HOT_TERMINAL_TURNS, SESSION_HISTORY_HOT_EFFECTS,
  SESSION_HISTORY_MAX_RECORDS,
  type CommandReceipt, type RuntimePointer, type SessionAggregateState,
  type SessionArchiveDelta, type SessionCommand, type SessionHistoryReadPlan,
  type SessionHistoryState,
} from "./types.ts";

const textEncoder = new TextEncoder();

// Planning runs before apply's canonical command validation. Invalid lookup keys
// must reach that validator without touching the archive or its stricter index
// key boundary. This is a lookup guard, not another command schema/parser.
function lookupIdentifier(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.isWellFormed() &&
    value === value.normalize("NFC") && textEncoder.encode(value).byteLength <= 256 &&
    !/\p{Cc}/u.test(value);
}

// Both archive planning and pure apply enforce this before any receipt lookup.
// Legacy internal callers may omit the pair; the signed public ingress cannot.
export function validatePublicAdmissionAuthority(state: SessionAggregateState, command: SessionCommand): void {
  if (command.kind !== "enqueue_turn" || command.publicAdmission === undefined) return;
  const admission = command.publicAdmission;
  if (admission === null || typeof admission !== "object") {
    sessionError("INVALID_ARGUMENT", "publicAdmission must be an object");
  }
  const scoped = admission.tenantId !== undefined || admission.actorSubjectId !== undefined;
  if (scoped && (!lookupIdentifier(admission.tenantId) || !lookupIdentifier(admission.actorSubjectId))) {
    sessionError("INVALID_ARGUMENT", "public admission tenant and actor must be supplied together");
  }
  if (scoped && (admission.tenantId !== state.tenantId || admission.actorSubjectId !== state.userId)) {
    sessionError("PERMISSION_DENIED", "public turn admission authority belongs to another principal");
  }
  if (!Number.isSafeInteger(admission.authorizationGeneration) || admission.authorizationGeneration < 0) {
    sessionError("INVALID_ARGUMENT", "public admission authorization generation is invalid");
  }
  if (admission.authorizationGeneration !== state.authorizationGeneration) {
    sessionError("STALE_GENERATION", "public turn admission authority is stale");
  }
}

/** Only absent hot keys need an authenticated lookup; no history scan is needed. */
export function planSessionHistoryReads(
  state: SessionAggregateState, command: SessionCommand,
): SessionHistoryReadPlan {
  const plan: SessionHistoryReadPlan = {};
  if (command?.kind === "broker_operation") {
    assertSessionBrokerAuthority(state, command.authority);
    validateSessionBrokerCommandShape(command);
    if (!lookupIdentifier(command.commandId) || !isDigest(command.operationKeyDigest)) {
      sessionError("INVALID_ARGUMENT", "broker command identity is malformed");
    }
    const kinds: Record<typeof command.operation, SessionBrokerReceiptKind> = {
      "acquire-step": "acquire", "commit-step": "commit", dispatch: "dispatch", "claim-start": "claim",
      confirm: "confirmation", settle: "settlement", block: "block", "prepare-retry": "retry", "settle-recovery": "recovery_settlement",
    };
    const kind = kinds[command.operation];
    // Claim keys are computed by the trusted host from the exact dispatch proof.
    const operationKey = command.operationKey;
    if (!state.broker?.receipts.some((receipt) => receipt.kind === kind && receipt.operationKeyDigest === command.operationKeyDigest)) {
      plan.brokerOperation = { kind, operationKey, operationKeyDigest: command.operationKeyDigest };
    }
    if (!state.commandReceipts.some((receipt) => receipt.commandId === command.commandId)) plan.commandId = command.commandId;
    if (command.operation === "commit-step" && command.body.step.kind === "effect_request") {
      if (lookupIdentifier(command.host.effectId)) plan.effectId = command.host.effectId;
      if (lookupIdentifier(command.host.invocationId)) plan.invocationId = command.host.invocationId;
    }
    if (command.operation === "claim-start" && state.broker?.dispatch !== null && state.broker?.dispatch !== undefined &&
      !state.commandReceipts.some((receipt) => receipt.committedEventSequence === state.broker!.dispatch!.eventSequence)) {
      plan.issuingEventSequence = state.broker.dispatch.eventSequence;
    }
    return plan;
  }
  if (command === null || typeof command !== "object" ||
    !lookupIdentifier(command.commandId) || !Number.isSafeInteger(command.expectedEventSequence) ||
    command.expectedEventSequence < 0 ||
    (command.kind === "commit_engine_step" && command.effectIdentity === undefined)) {
    return plan;
  }
  validatePublicAdmissionAuthority(state, command);
  if (!state.commandReceipts.some((receipt) => receipt.commandId === command.commandId)) {
    plan.commandId = command.commandId;
  }
  if (command.kind === "enqueue_turn") {
    if (lookupIdentifier(command.turnId) && !state.knownTurnIds.includes(command.turnId)) plan.turnId = command.turnId;
    const key = command.publicAdmission?.idempotencyKeyDigest;
    if (isDigest(key) && !state.turnAdmissionReceipts.some((receipt) => receipt.idempotencyKeyDigest === key)) {
      plan.idempotencyKeyDigest = key;
    }
  }
  const effectId = command.kind === "commit_engine_step"
    ? command.effectIdentity?.effectId
    : "effectId" in command ? command.effectId : undefined;
  if (lookupIdentifier(effectId) && !state.effects.some((effect) => effect.effectId === effectId)) {
    plan.effectId = effectId;
  }
  if (command.kind === "commit_engine_step" && lookupIdentifier(command.effectIdentity?.invocationId) &&
    !state.effects.some((effect) => effect.invocationId === command.effectIdentity?.invocationId)) {
    plan.invocationId = command.effectIdentity.invocationId;
  }
  if (command.kind === "claim_dispatch_start" &&
    !state.commandReceipts.some((receipt) => receipt.committedEventSequence === command.expectedEventSequence)) {
    plan.issuingEventSequence = command.expectedEventSequence;
  }
  return plan;
}

function advancePointer(pointer: RuntimePointer, receipts: readonly CommandReceipt[]): RuntimePointer {
  const result = structuredClone(pointer);
  for (const { outcome } of receipts) {
    if (outcome.kind === "runtime_revision_staged") result.candidateRevision = outcome.candidateRevision;
    else if (outcome.kind === "runtime_candidate_discarded") result.candidateRevision = null;
    else if (outcome.kind === "runtime_revision_activated" || outcome.kind === "runtime_revision_rolled_back") {
      result.activeRevision = outcome.activeRevision;
      result.previousRevision = outcome.previousRevision;
      result.candidateRevision = null;
      result.switchGeneration = outcome.switchGeneration;
    }
  }
  return result;
}

function initialHistory(state: SessionAggregateState): SessionHistoryState {
  const firstRuntime = state.commandReceipts.find(({ outcome }) => outcome.kind === "runtime_revision_staged");
  const initialRevision = firstRuntime?.outcome.kind === "runtime_revision_staged"
    ? firstRuntime.outcome.activeRevision : state.runtimeRevisionDigest;
  return {
    commandThrough: 0, publicEventThrough: 0, turnThrough: 0,
    runtimePointerAtCommandThrough: {
      activeRevision: initialRevision, candidateRevision: null, previousRevision: null, switchGeneration: 1,
    },
    latestSettledTurnAtTurnThrough: null,
    publicEventAnchors: [], dispatchStartReceipts: [], runtimeRevisionDigests: [],
  };
}

/** A bounded immutable archive delta. The caller persists it atomically with state. */
export function compactSessionHistory(
  state: SessionAggregateState, maxRecords = SESSION_HISTORY_MAX_RECORDS,
): { state: SessionAggregateState; archive: SessionArchiveDelta } {
  if (!Number.isSafeInteger(maxRecords) || maxRecords < 0 || maxRecords > SESSION_HISTORY_MAX_RECORDS) {
    sessionError("INVALID_ARGUMENT", "history archive batch exceeds its bounded record budget");
  }
  const next = structuredClone(state);
  const history = next.history ?? initialHistory(next);
  const archive: SessionArchiveDelta = {
    commandReceipts: [], publicEvents: [], terminalTurns: [], effects: [],
    turnAdmissionReceipts: [], turnIdentities: [],
  };
  let remaining = maxRecords;
  const pressuredTurnIds = new Set(next.terminalTurns.slice(0, -SESSION_HISTORY_HOT_TERMINAL_TURNS).map((turn) => turn.turnId));
  const pressuredEffectIds = new Set(next.effects.filter((effect, index) =>
    (effect.consumedAtCheckpointSequence !== null || effect.consumedByAbort) &&
    (index < next.effects.length - SESSION_HISTORY_HOT_EFFECTS || pressuredTurnIds.has(effect.turnId)))
    .map((effect) => effect.effectId));
  const lastPinnedClaim = next.commandReceipts.findLastIndex(({ outcome }) =>
    outcome.kind === "dispatch_start_claimed" && pressuredEffectIds.has(outcome.effectId));
  const commands = Math.min(remaining, Math.max(0, next.commandReceipts.length - SESSION_HISTORY_HOT_COMMANDS, lastPinnedClaim + 1));
  archive.commandReceipts = next.commandReceipts.splice(0, commands);
  remaining -= commands;
  history.runtimePointerAtCommandThrough = advancePointer(history.runtimePointerAtCommandThrough, archive.commandReceipts);
  history.commandThrough += commands;
  if (next.broker !== undefined) {
    const receipts = Math.min(remaining, Math.max(0, next.broker.receipts.length - SESSION_BROKER_HOT_RECEIPTS));
    if (receipts > 0) {
      archive.brokerReceipts = next.broker.receipts.splice(0, receipts);
      next.broker.receiptsThrough += receipts;
      remaining -= receipts;
    }
  }
  const lastPinnedEvent = next.publicEvents.findLastIndex((event) =>
    pressuredTurnIds.has(event.turnId) || ("effectId" in event && pressuredEffectIds.has(event.effectId)));
  const events = Math.min(remaining, Math.max(0, next.publicEvents.length - SESSION_HISTORY_HOT_PUBLIC_EVENTS, lastPinnedEvent + 1));
  archive.publicEvents = next.publicEvents.splice(0, events);
  remaining -= events;
  history.publicEventThrough += events;

  const retainedEventEffectIds = new Set(next.publicEvents.flatMap((event) => "effectId" in event ? [event.effectId] : []));
  const retainedStartEffectIds = new Set(next.commandReceipts.flatMap(({ outcome }) => outcome.kind === "dispatch_start_claimed" ? [outcome.effectId] : []));
  for (let index = 0; index < next.effects.length && remaining > 0;) {
    const effect = next.effects[index]!;
    if ((next.effects.length > SESSION_HISTORY_HOT_EFFECTS ||
      next.terminalTurns.slice(0, -SESSION_HISTORY_HOT_TERMINAL_TURNS).some((turn) => turn.turnId === effect.turnId)) &&
      (effect.consumedAtCheckpointSequence !== null || effect.consumedByAbort) &&
      !retainedEventEffectIds.has(effect.effectId) && !retainedStartEffectIds.has(effect.effectId)) {
      archive.effects.push(...next.effects.splice(index, 1));
      remaining -= 1;
    } else index += 1;
  }
  while (next.terminalTurns.length > SESSION_HISTORY_HOT_TERMINAL_TURNS) {
    const turn = next.terminalTurns[0]!;
    const receipt = next.turnAdmissionReceipts.find((entry) => entry.turnId === turn.turnId);
    const cost = receipt === undefined ? 2 : 3;
    if (remaining < cost || next.effects.some((effect) => effect.turnId === turn.turnId) ||
      next.publicEvents.some((event) => event.turnId === turn.turnId)) break;
    archive.terminalTurns.push(next.terminalTurns.shift()!);
    archive.turnIdentities.push({ turnId: turn.turnId, turnSequence: turn.sequence });
    if (receipt !== undefined) {
      archive.turnAdmissionReceipts.push(receipt);
      next.turnAdmissionReceipts = next.turnAdmissionReceipts.filter((entry) => entry !== receipt);
    }
    next.knownTurnIds.shift();
    history.turnThrough += 1;
    history.latestSettledTurnAtTurnThrough = turn.turnId;
    remaining -= cost;
  }
  if (remaining === maxRecords) return { state: next, archive };
  const hotTurnIds = new Set(next.knownTurnIds);
  const hotEffectIds = new Set(next.effects.map((effect) => effect.effectId));
  const anchorKeys = new Set<string>();
  history.publicEventAnchors = [...history.publicEventAnchors, ...archive.publicEvents].filter((event) => {
    if (!hotTurnIds.has(event.turnId) || ("effectId" in event && !hotEffectIds.has(event.effectId))) return false;
    const key = JSON.stringify([event.type, "effectId" in event ? event.effectId : event.turnId]);
    if (anchorKeys.has(key)) return false;
    anchorKeys.add(key);
    return true;
  });
  history.dispatchStartReceipts = [...history.dispatchStartReceipts, ...archive.commandReceipts].filter(({ outcome }) =>
    outcome.kind === "dispatch_start_claimed" && hotEffectIds.has(outcome.effectId));
  // These revisions were validated against the prior prefix and retained receipts.
  // Keep only the evidence that surviving terminal checkpoints still reference.
  history.runtimeRevisionDigests = [...new Set<Digest>(next.terminalTurns.map((turn) => turn.finalCheckpoint.runtimeRevisionDigest))];
  next.history = history;
  return { state: next, archive };
}
