import {
  ProtocolValidationError,
  digestStructuredValue,
  encodeCanonicalCbor,
  normalizeProtocolValue,
  parseDigest,
  type Digest,
  type NormalizedValue,
} from "@circulusd/protocol-types";

import { controlError, type ControlAggregateErrorCode } from "./errors.ts";
import type {
  ControlAuthoritySnapshot,
  ControlPermission,
  ControlRole,
  ControlSubjectKind,
} from "./types.ts";

export const CONTROL_IDENTIFIER_MAX_BYTES = 256;
export const USER_VALUE_MAX_BYTES = 256 * 1_024;
export const USER_STATE_MAX_BYTES = 2 * 1_024 * 1_024;
export const EXTENSION_VALUE_MAX_BYTES = 512 * 1_024;
export const EXTENSION_STATE_MAX_BYTES = 2 * 1_024 * 1_024;
export const GENERATION_STATE_MAX_BYTES = 2 * 1_024 * 1_024;
export const AUDIT_EVENT_MAX_BYTES = 64 * 1_024;
export const AUDIT_STATE_MAX_BYTES = 3 * 1_024 * 1_024;

const textEncoder = new TextEncoder();

export function compareUtf8(left: string, right: string): number {
  const leftBytes = textEncoder.encode(left);
  const rightBytes = textEncoder.encode(right);
  const length = Math.min(leftBytes.byteLength, rightBytes.byteLength);
  for (let index = 0; index < length; index += 1) {
    const difference = (leftBytes[index] ?? 0) - (rightBytes[index] ?? 0);
    if (difference !== 0) {
      return difference;
    }
  }
  return leftBytes.byteLength - rightBytes.byteLength;
}

export function validatedDataArray(
  value: unknown,
  field: string,
  maximumLength = 4_096,
): unknown[] {
  if (!Array.isArray(value)) {
    controlError("INVALID_ARGUMENT", `${field} must be an array`);
  }
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  if (
    lengthDescriptor === undefined ||
    !("value" in lengthDescriptor) ||
    !Number.isSafeInteger(lengthDescriptor.value) ||
    lengthDescriptor.value > maximumLength
  ) {
    controlError("INVALID_ARGUMENT", `${field} exceeds its bounded array length`);
  }
  const length = lengthDescriptor.value as number;
  const result: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (
      descriptor === undefined ||
      !descriptor.enumerable ||
      !("value" in descriptor)
    ) {
      controlError(
        "INVALID_ARGUMENT",
        `${field}[${index}] must be an enumerable data property`,
      );
    }
    result.push(descriptor.value);
  }
  for (const key of Reflect.ownKeys(value)) {
    if (key === "length") {
      continue;
    }
    if (
      typeof key !== "string" ||
      !/^(0|[1-9][0-9]*)$/.test(key) ||
      Number(key) >= length
    ) {
      controlError("INVALID_ARGUMENT", `${field} has unknown field ${String(key)}`);
    }
  }
  return result;
}

const CONTROL_AUTHORITY_FIELDS = [
  "serviceBinding",
  "tenantId",
  "actorUserId",
  "subjectKind",
  "subjectId",
  "roles",
  "permissions",
  "authorizationGeneration",
  "currentAuthorizationGeneration",
  "issuedAt",
  "expiresAt",
] as const;

const CONTROL_ROLES: readonly ControlRole[] = [
  "platform-admin",
  "tenant-admin",
  "workspace-owner",
  "workspace-member",
  "user",
];

const CONTROL_PERMISSIONS: readonly ControlPermission[] = [
  "session.read",
  "user.read",
  "user.preferences.write",
  "user.quota.write",
  "extension-state.read",
  "extension-state.write",
  "generation.read",
  "generation.rotate",
  "audit.read",
  "audit.append",
];

const SUBJECT_KINDS: readonly ControlSubjectKind[] = [
  "tenant",
  "user",
  "workspace",
  "session",
];

export function validatedDataRecord(
  value: unknown,
  field: string,
  errorCode: ControlAggregateErrorCode = "INVALID_ARGUMENT",
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    controlError(errorCode, `${field} must be a plain object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    controlError(errorCode, `${field} must be a plain object`);
  }
  const record = value as Record<string, unknown>;
  for (const key of Reflect.ownKeys(record)) {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (
      typeof key !== "string" ||
      descriptor === undefined ||
      !descriptor.enumerable ||
      !("value" in descriptor)
    ) {
      controlError(errorCode, `${field}.${String(key)} must be an enumerable data property`);
    }
  }
  return record;
}

export function validatedExactFields(
  value: unknown,
  required: readonly string[],
  optional: readonly string[],
  field: string,
  errorCode: ControlAggregateErrorCode = "INVALID_ARGUMENT",
): Record<string, unknown> {
  const record = validatedDataRecord(value, field, errorCode);
  for (const key of Reflect.ownKeys(record)) {
    if (
      typeof key !== "string" ||
      (!required.includes(key) && !optional.includes(key))
    ) {
      controlError(errorCode, `${field} has unknown field ${String(key)}`);
    }
  }
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(record, key)) {
      controlError(errorCode, `${field} is missing field ${key}`);
    }
  }
  return record;
}

export function validatedIdentifier(value: unknown, field: string): string {
  let normalized: NormalizedValue;
  try {
    normalized = normalizeProtocolValue(value);
  } catch (error) {
    if (error instanceof ProtocolValidationError) {
      controlError("INVALID_ARGUMENT", `${field}: ${error.message}`);
    }
    throw error;
  }
  if (typeof normalized !== "string" || normalized.length === 0) {
    controlError("INVALID_ARGUMENT", `${field} must be a non-empty string`);
  }
  if (normalized !== value) {
    controlError("INVALID_ARGUMENT", `${field} must be NFC-normalized`);
  }
  if (
    textEncoder.encode(normalized).byteLength > CONTROL_IDENTIFIER_MAX_BYTES ||
    /\p{Cc}/u.test(normalized)
  ) {
    controlError("INVALID_ARGUMENT", `${field} is not a valid protocol identifier`);
  }
  return normalized;
}

export function validatedInteger(
  value: unknown,
  field: string,
  minimum: number,
): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) {
    controlError(
      "INVALID_ARGUMENT",
      `${field} must be a safe integer greater than or equal to ${minimum}`,
    );
  }
  return value;
}

export function validatedDigest(value: unknown, field: string): Digest {
  try {
    return parseDigest(value, field);
  } catch (error) {
    if (error instanceof ProtocolValidationError) {
      controlError("INVALID_ARGUMENT", error.message);
    }
    throw error;
  }
}

function assertCanonicalStrings(value: unknown, field: string): void {
  const pending: Array<{ readonly value: unknown; readonly field: string }> = [
    { value, field },
  ];
  while (pending.length > 0) {
    const current = pending.pop();
    if (current === undefined) {
      continue;
    }
    if (typeof current.value === "string") {
      if (current.value !== current.value.normalize("NFC")) {
        controlError("INVALID_ARGUMENT", `${current.field} must be NFC-normalized`);
      }
      continue;
    }
    if (
      current.value === null ||
      typeof current.value !== "object" ||
      current.value instanceof Uint8Array
    ) {
      continue;
    }
    if (Array.isArray(current.value)) {
      for (const [index, entry] of current.value.entries()) {
        pending.push({ value: entry, field: `${current.field}[${index}]` });
      }
      continue;
    }
    for (const key of Object.keys(current.value)) {
      if (key !== key.normalize("NFC")) {
        controlError("INVALID_ARGUMENT", `${current.field} has a non-NFC field name`);
      }
      pending.push({
        value: (current.value as Record<string, unknown>)[key],
        field: `${current.field}.${key}`,
      });
    }
  }
}

export function validatedBoundedValue(
  value: unknown,
  field: string,
  maxBytes: number,
): NormalizedValue {
  try {
    const normalized = normalizeProtocolValue(value);
    assertCanonicalStrings(value, field);
    encodeCanonicalCbor(normalized, { maxBytes });
    return normalized;
  } catch (error) {
    if (error instanceof ProtocolValidationError) {
      const code = error.message.includes("encoded size exceeds")
        ? "RESOURCE_EXHAUSTED"
        : "INVALID_ARGUMENT";
      controlError(code, `${field}: ${error.message}`);
    }
    throw error;
  }
}

export function assertEncodedSize(
  value: unknown,
  field: string,
  maxBytes: number,
  errorCode: ControlAggregateErrorCode,
): void {
  try {
    const normalized = normalizeProtocolValue(value);
    assertCanonicalStrings(value, field);
    encodeCanonicalCbor(normalized, { maxBytes });
  } catch (error) {
    if (error instanceof ProtocolValidationError) {
      controlError(errorCode, `${field}: ${error.message}`);
    }
    throw error;
  }
}

export function validatedAuthority(
  value: unknown,
  target: {
    readonly tenantId: string;
    readonly subjectKind: ControlSubjectKind;
    readonly subjectId: string;
  },
  nowInput: unknown,
  requiredPermission: ControlPermission,
): ControlAuthoritySnapshot {
  const now = validatedInteger(nowInput, "now", 0);
  const record = validatedExactFields(
    value,
    CONTROL_AUTHORITY_FIELDS,
    [],
    "authority",
  );
  if (record.serviceBinding !== "state") {
    controlError("PERMISSION_DENIED", "authority service binding must be state");
  }
  const tenantId = validatedIdentifier(record.tenantId, "authority.tenantId");
  const actorUserId = validatedIdentifier(record.actorUserId, "authority.actorUserId");
  if (!SUBJECT_KINDS.includes(record.subjectKind as ControlSubjectKind)) {
    controlError("INVALID_ARGUMENT", "authority.subjectKind is invalid");
  }
  const subjectKind = record.subjectKind as ControlSubjectKind;
  const subjectId = validatedIdentifier(record.subjectId, "authority.subjectId");
  const roleCandidates = validatedDataArray(record.roles, "authority.roles", 5);
  const roles: ControlRole[] = [];
  let previousRole: string | null = null;
  for (const candidate of roleCandidates) {
    if (typeof candidate !== "string" || !CONTROL_ROLES.includes(candidate as ControlRole)) {
      controlError("INVALID_ARGUMENT", "authority.roles contains an unknown value");
    }
    if (previousRole !== null && compareUtf8(candidate, previousRole) <= 0) {
      controlError("INVALID_ARGUMENT", "authority.roles must be a sorted unique set");
    }
    previousRole = candidate;
    roles.push(candidate as ControlRole);
  }
  const permissionCandidates = validatedDataArray(
    record.permissions,
    "authority.permissions",
    CONTROL_PERMISSIONS.length,
  );
  const permissions: ControlPermission[] = [];
  let previousPermission: string | null = null;
  for (const candidate of permissionCandidates) {
    if (
      typeof candidate !== "string" ||
      !CONTROL_PERMISSIONS.includes(candidate as ControlPermission)
    ) {
      controlError("INVALID_ARGUMENT", "authority.permissions contains an unknown value");
    }
    if (
      previousPermission !== null &&
      compareUtf8(candidate, previousPermission) <= 0
    ) {
      controlError("INVALID_ARGUMENT", "authority.permissions must be a sorted unique set");
    }
    previousPermission = candidate;
    permissions.push(candidate as ControlPermission);
  }
  const authorizationGeneration = validatedInteger(
    record.authorizationGeneration,
    "authority.authorizationGeneration",
    1,
  );
  const currentAuthorizationGeneration = validatedInteger(
    record.currentAuthorizationGeneration,
    "authority.currentAuthorizationGeneration",
    1,
  );
  if (authorizationGeneration !== currentAuthorizationGeneration) {
    controlError(
      "STALE_GENERATION",
      "authority authorizationGeneration is not current",
    );
  }
  const issuedAt = validatedInteger(record.issuedAt, "authority.issuedAt", 0);
  const expiresAt = validatedInteger(record.expiresAt, "authority.expiresAt", 1);
  if (issuedAt > now || now >= expiresAt) {
    controlError("PERMISSION_DENIED", "authority is not valid at the transaction time");
  }
  if (
    tenantId !== target.tenantId ||
    subjectKind !== target.subjectKind ||
    subjectId !== target.subjectId
  ) {
    controlError("PERMISSION_DENIED", "authority does not match the tenant and subject ACL");
  }
  if (!permissions.includes(requiredPermission)) {
    controlError("PERMISSION_DENIED", `${requiredPermission} permission is required`);
  }
  return structuredClone({
    serviceBinding: "state" as const,
    tenantId,
    actorUserId,
    subjectKind,
    subjectId,
    roles,
    permissions,
    authorizationGeneration,
    currentAuthorizationGeneration,
    issuedAt,
    expiresAt,
  });
}

export async function semanticCommandDigest(
  domain: string,
  semanticCommand: unknown,
): Promise<Digest> {
  try {
    return await digestStructuredValue(domain, 1, semanticCommand);
  } catch (error) {
    if (error instanceof ProtocolValidationError) {
      controlError("INVALID_ARGUMENT", `command is not serializable: ${error.message}`);
    }
    throw error;
  }
}
