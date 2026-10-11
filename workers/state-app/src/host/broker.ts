import { digestStructuredValue } from "@circulusd/protocol-types";
import {
  brokerExact, parseSessionBrokerAuthority, parseSessionBrokerPolicy, parseSessionBrokerRequest,
} from "../session/broker-validation.ts";
import { sessionBrokerOperationIdentity } from "../session/broker.ts";
import { sessionError } from "../session/errors.ts";
import type {
  SessionBrokerAuthority, SessionBrokerCommand, SessionBrokerPolicy, SessionBrokerRequest,
} from "../session/broker-types.ts";

export type SessionBrokerPayload = SessionBrokerRequest & { authority: SessionBrokerAuthority };

export function parseTypedBrokerPayload(value: unknown): SessionBrokerPayload {
  const fields = brokerExact(value, ["authority", "operation", "body"], "broker payload");
  return { ...parseSessionBrokerRequest({ operation: fields.operation, body: fields.body }),
    authority: parseSessionBrokerAuthority(fields.authority) };
}

export function sessionBrokerHostPolicy(value: unknown): SessionBrokerPolicy | null {
  if (value === undefined) return null;
  try { return parseSessionBrokerPolicy(typeof value === "string" ? JSON.parse(value) : value); }
  catch { sessionError("FAILED_PRECONDITION", "trusted Session broker runtime policy is invalid"); }
}

// The entropy is authority-owned and retained through transaction retries. These
// IDs use the same 128-bit unpadded RFC4648 base32 format as Go identity.ID.
function identity(prefix: "effect" | "inv"): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let encoded = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) { bits -= 5; encoded += alphabet[(value >>> bits) & 31]; }
  }
  if (bits > 0) encoded += alphabet[(value << (5 - bits)) & 31];
  return `${prefix}_${encoded}`;
}

export async function brokerCommand(payload: SessionBrokerPayload, policy: SessionBrokerPolicy): Promise<SessionBrokerCommand> {
  if (payload.operation === "read-turn" || payload.operation === "lookup-operation") sessionError("INVALID_ARGUMENT", "broker query cannot become a mutation");
  const operation = await sessionBrokerOperationIdentity(payload);
  return { operation: payload.operation, body: payload.body, kind: "broker_operation",
    commandId: `broker:${operation.kind}:${operation.operationKeyDigest}`,
    expectedEventSequence: payload.body.snapshot.eventSequence, operationKey: operation.operationKey,
    operationKeyDigest: operation.operationKeyDigest, authority: payload.authority,
    host: { policy: structuredClone(policy), opaque: crypto.getRandomValues(new Uint8Array(32)),
      secondaryOpaque: crypto.getRandomValues(new Uint8Array(32)), effectId: identity("effect"), invocationId: identity("inv") } } as SessionBrokerCommand;
}

export function brokerLookupKey(operationKey: string) {
  return digestStructuredValue("circulusd.session.broker.operation-key", 1, operationKey);
}
