import {
  ProtocolValidationError,
  digestStructuredValue,
  normalizeProtocolValue,
  parseDigest,
  type Digest,
} from "@circulusd/protocol-types";

import { workspaceError } from "./errors.ts";
import {
  WORKSPACE_COMMAND_SCHEMA_VERSION,
  WORKSPACE_STATE_SCHEMA_VERSION,
  type AcquireWriteLeaseCommand,
  type ApplyWorkspaceCommandResult,
  type CreateWorkspaceStateInput,
  type WorkspaceAggregateState,
  type WorkspaceAuthoritySnapshot,
  type WorkspaceBackend,
  type WorkspaceCommand,
  type WorkspaceCommandOutcome,
  type WorkspaceInvocationRecord,
  type WorkspaceLeaseConflictRecord,
  type WorkspaceLeaseFence,
  type WorkspaceLeaseHistoryRecord,
  type WorkspaceLeaseQueueEntry,
  type WorkspaceMaterializationTicket,
  type WorkspacePermission,
  type WorkspaceProtectionProof,
  type WorkspaceRevision,
  type WorkspaceWriteLeaseConflictOutcome,
  type WorkspaceWriteLease,
} from "./types.ts";

const textEncoder = new TextEncoder();

function compareUtf8(left: string, right: string): number {
  const leftBytes = textEncoder.encode(left);
  const rightBytes = textEncoder.encode(right);
  const sharedLength = Math.min(leftBytes.byteLength, rightBytes.byteLength);
  for (let index = 0; index < sharedLength; index += 1) {
    const difference = (leftBytes[index] ?? 0) - (rightBytes[index] ?? 0);
    if (difference !== 0) {
      return difference;
    }
  }
  return leftBytes.byteLength - rightBytes.byteLength;
}

const WORKSPACE_AUTHORITY_FIELDS = [
  "purpose",
  "serviceBinding",
  "tenantId",
  "userId",
  "sessionId",
  "workspaceId",
  "turnId",
  "runtimeRevision",
  "policySnapshotDigest",
  "emergencyOverlayDigest",
  "effectivePermissions",
  "sessionStatus",
  "turnStatus",
  "turnLeaseActive",
  "turnLeaseExpiresAt",
  "effectStatus",
  "effectId",
  "invocationId",
  "requestDigest",
  "replayPolicy",
  "dispatchAttempt",
  "sandboxId",
  "backend",
  "turnLeaseGeneration",
  "placementGeneration",
  "sandboxGeneration",
  "authorizationGeneration",
  "issuedAt",
  "expiresAt",
] as const;

function validatedDataRecord(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    workspaceError("INVALID_ARGUMENT", `${field} must be an object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    workspaceError("INVALID_ARGUMENT", `${field} must be a plain object`);
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
      workspaceError(
        "INVALID_ARGUMENT",
        `${field}.${String(key)} must be an enumerable data property`,
      );
    }
  }
  return record;
}

function validatedExactKeys(
  value: unknown,
  fields: readonly string[],
  field: string,
): Record<string, unknown> {
  const record = validatedDataRecord(value, field);
  for (const key of Reflect.ownKeys(record)) {
    if (typeof key !== "string" || !fields.includes(key)) {
      workspaceError("INVALID_ARGUMENT", `${field} has unknown field ${String(key)}`);
    }
  }
  for (const key of fields) {
    if (!Object.prototype.hasOwnProperty.call(record, key)) {
      workspaceError("INVALID_ARGUMENT", `${field} is missing field ${key}`);
    }
  }
  return record;
}

function validatedIdentifier(value: unknown, field: string): string {
  let normalized;
  try {
    normalized = normalizeProtocolValue(value);
  } catch (error) {
    if (error instanceof ProtocolValidationError) {
      workspaceError("INVALID_ARGUMENT", `${field}: ${error.message}`);
    }
    throw error;
  }
  if (typeof normalized !== "string" || normalized.length === 0) {
    workspaceError("INVALID_ARGUMENT", `${field} must be a non-empty string`);
  }
  if (normalized !== value) {
    workspaceError("INVALID_ARGUMENT", `${field} must be NFC-normalized`);
  }
  if (textEncoder.encode(normalized).byteLength > 256 || /\p{Cc}/u.test(normalized)) {
    workspaceError("INVALID_ARGUMENT", `${field} is not a valid protocol identifier`);
  }
  return normalized;
}

function validatedInteger(value: unknown, field: string, minimum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) {
    workspaceError(
      "INVALID_ARGUMENT",
      `${field} must be a safe integer greater than or equal to ${minimum}`,
    );
  }
  return value;
}

function checkedAdd(left: number, right: number, field: string): number {
  const result = left + right;
  if (!Number.isSafeInteger(result)) {
    workspaceError("INVALID_ARGUMENT", `${field} exceeds the safe integer range`);
  }
  return result;
}

function validatedBackend(value: unknown, field: string): WorkspaceBackend {
  if (value !== "nsjail" && value !== "docker" && value !== "firecracker") {
    workspaceError("INVALID_ARGUMENT", `${field} must be nsjail, docker, or firecracker`);
  }
  return value;
}

function validatedAuthority(
  value: unknown,
  state: WorkspaceAggregateState,
  field: string,
  now: number | null,
  requiredPermission: WorkspacePermission | null,
  requiredPurpose: "admission" | "settlement" | null,
): WorkspaceAuthoritySnapshot {
  const record = validatedExactKeys(value, WORKSPACE_AUTHORITY_FIELDS, field);
  if (record.purpose !== "admission" && record.purpose !== "settlement") {
    workspaceError("INVALID_ARGUMENT", `${field}.purpose is invalid`);
  }
  if (requiredPurpose !== null && record.purpose !== requiredPurpose) {
    workspaceError("PERMISSION_DENIED", `${field}.purpose cannot authorize this operation`);
  }
  if (record.serviceBinding !== "workspace") {
    workspaceError("PERMISSION_DENIED", `${field}.serviceBinding must be workspace`);
  }
  validatedIdentifier(record.tenantId, `${field}.tenantId`);
  validatedIdentifier(record.userId, `${field}.userId`);
  validatedIdentifier(record.sessionId, `${field}.sessionId`);
  validatedIdentifier(record.workspaceId, `${field}.workspaceId`);
  validatedIdentifier(record.turnId, `${field}.turnId`);
  validatedIdentifier(record.runtimeRevision, `${field}.runtimeRevision`);
  parseDigest(record.policySnapshotDigest, `${field}.policySnapshotDigest`);
  parseDigest(record.emergencyOverlayDigest, `${field}.emergencyOverlayDigest`);
  if (!Array.isArray(record.effectivePermissions)) {
    workspaceError("INVALID_ARGUMENT", `${field}.effectivePermissions must be an array`);
  }
  let previousPermission = "";
  for (const permission of record.effectivePermissions) {
    if (permission !== "workspace.read" && permission !== "workspace.write") {
      workspaceError("INVALID_ARGUMENT", `${field}.effectivePermissions contains an invalid value`);
    }
    if (permission <= previousPermission) {
      workspaceError(
        "INVALID_ARGUMENT",
        `${field}.effectivePermissions must be a unique sorted set`,
      );
    }
    previousPermission = permission;
  }
  if (
    requiredPermission !== null &&
    !record.effectivePermissions.includes(requiredPermission)
  ) {
    workspaceError("PERMISSION_DENIED", `${requiredPermission} permission is required`);
  }
  if (record.sessionStatus !== "active" && record.sessionStatus !== "closed") {
    workspaceError("INVALID_ARGUMENT", `${field}.sessionStatus is invalid`);
  }
  if (
    record.turnStatus !== "active" &&
    record.turnStatus !== "settling" &&
    record.turnStatus !== "aborting" &&
    record.turnStatus !== "completed"
  ) {
    workspaceError("INVALID_ARGUMENT", `${field}.turnStatus is invalid`);
  }
  if (typeof record.turnLeaseActive !== "boolean") {
    workspaceError("INVALID_ARGUMENT", `${field}.turnLeaseActive must be boolean`);
  }
  const turnLeaseExpiresAt = validatedInteger(
    record.turnLeaseExpiresAt,
    `${field}.turnLeaseExpiresAt`,
    1,
  );
  if (
    record.effectStatus !== "prepared" &&
    record.effectStatus !== "dispatched" &&
    record.effectStatus !== "externally_committed"
  ) {
    workspaceError("INVALID_ARGUMENT", `${field}.effectStatus is invalid`);
  }
  validatedIdentifier(record.effectId, `${field}.effectId`);
  validatedIdentifier(record.invocationId, `${field}.invocationId`);
  parseDigest(record.requestDigest, `${field}.requestDigest`);
  if (
    record.replayPolicy !== "safe" &&
    record.replayPolicy !== "idempotency-key" &&
    record.replayPolicy !== "never" &&
    record.replayPolicy !== "confirm"
  ) {
    workspaceError("INVALID_ARGUMENT", `${field}.replayPolicy is invalid`);
  }
  validatedInteger(record.dispatchAttempt, `${field}.dispatchAttempt`, 1);
  validatedIdentifier(record.sandboxId, `${field}.sandboxId`);
  validatedBackend(record.backend, `${field}.backend`);
  validatedInteger(record.turnLeaseGeneration, `${field}.turnLeaseGeneration`, 0);
  validatedInteger(record.placementGeneration, `${field}.placementGeneration`, 0);
  validatedInteger(record.sandboxGeneration, `${field}.sandboxGeneration`, 0);
  validatedInteger(record.authorizationGeneration, `${field}.authorizationGeneration`, 0);
  const issuedAt = validatedInteger(record.issuedAt, `${field}.issuedAt`, 0);
  const expiresAt = validatedInteger(record.expiresAt, `${field}.expiresAt`, 1);
  if (issuedAt >= expiresAt) {
    workspaceError("INVALID_ARGUMENT", `${field} time bounds are invalid`);
  }
  if (record.tenantId !== state.tenantId || record.workspaceId !== state.workspaceId) {
    workspaceError("PERMISSION_DENIED", `${field} scope does not match the workspace`);
  }
  if (now !== null) {
    if (
      record.sessionStatus !== "active" ||
      record.turnStatus === "completed" ||
      record.turnLeaseActive !== true ||
      now >= turnLeaseExpiresAt
    ) {
      workspaceError("FAILED_PRECONDITION", `${field} is not backed by an active turn lease`);
    }
    if (now < issuedAt) {
      workspaceError("FAILED_PRECONDITION", `${field} was issued in the future`);
    }
    if (
      record.purpose === "admission" &&
      (record.turnStatus !== "active" ||
        record.effectStatus === "externally_committed" ||
        now >= expiresAt)
    ) {
      workspaceError("FAILED_PRECONDITION", `${field} cannot admit a new operation`);
    }
    if (
      record.purpose === "settlement" &&
      record.effectStatus !== "dispatched" &&
      record.effectStatus !== "externally_committed"
    ) {
      workspaceError("FAILED_PRECONDITION", `${field} effect is not settleable`);
    }
  }
  return structuredClone(record) as unknown as WorkspaceAuthoritySnapshot;
}

function authorityIdentityMatches(
  left: WorkspaceAuthoritySnapshot,
  right: WorkspaceAuthoritySnapshot,
): boolean {
  return (
    left.tenantId === right.tenantId &&
    left.userId === right.userId &&
    left.sessionId === right.sessionId &&
    left.workspaceId === right.workspaceId &&
    left.turnId === right.turnId &&
    left.runtimeRevision === right.runtimeRevision &&
    left.policySnapshotDigest === right.policySnapshotDigest &&
    left.emergencyOverlayDigest === right.emergencyOverlayDigest &&
    left.effectivePermissions.length === right.effectivePermissions.length &&
    left.effectivePermissions.every(
      (permission, index) => permission === right.effectivePermissions[index],
    ) &&
    left.effectId === right.effectId &&
    left.invocationId === right.invocationId &&
    left.requestDigest === right.requestDigest &&
    left.replayPolicy === right.replayPolicy &&
    left.dispatchAttempt === right.dispatchAttempt &&
    left.sandboxId === right.sandboxId &&
    left.backend === right.backend &&
    left.turnLeaseGeneration === right.turnLeaseGeneration &&
    left.placementGeneration === right.placementGeneration &&
    left.sandboxGeneration === right.sandboxGeneration &&
    left.authorizationGeneration === right.authorizationGeneration
  );
}

function stableSettlementIdentityMatches(
  current: WorkspaceAuthoritySnapshot,
  historical: WorkspaceAuthoritySnapshot,
): boolean {
  return (
    current.tenantId === historical.tenantId &&
    current.userId === historical.userId &&
    current.sessionId === historical.sessionId &&
    current.workspaceId === historical.workspaceId &&
    current.turnId === historical.turnId &&
    current.runtimeRevision === historical.runtimeRevision &&
    current.policySnapshotDigest === historical.policySnapshotDigest &&
    current.effectId === historical.effectId &&
    current.invocationId === historical.invocationId &&
    current.requestDigest === historical.requestDigest &&
    current.replayPolicy === historical.replayPolicy &&
    current.dispatchAttempt === historical.dispatchAttempt &&
    current.sandboxId === historical.sandboxId &&
    current.backend === historical.backend
  );
}

function authorizationRotationIsMonotonicAndNonWidening(
  current: WorkspaceAuthoritySnapshot,
  historical: WorkspaceAuthoritySnapshot,
): boolean {
  if (current.authorizationGeneration < historical.authorizationGeneration) {
    return false;
  }
  if (current.authorizationGeneration === historical.authorizationGeneration) {
    return (
      current.emergencyOverlayDigest === historical.emergencyOverlayDigest &&
      current.effectivePermissions.length === historical.effectivePermissions.length &&
      current.effectivePermissions.every(
        (permission, index) => permission === historical.effectivePermissions[index],
      )
    );
  }
  return current.effectivePermissions.every((permission) =>
    historical.effectivePermissions.includes(permission),
  );
}

function authorityCanRefreshQueuedAdmission(
  current: WorkspaceAuthoritySnapshot,
  historical: WorkspaceAuthoritySnapshot,
): boolean {
  return (
    stableSettlementIdentityMatches(current, historical) &&
    current.turnLeaseGeneration === historical.turnLeaseGeneration &&
    current.placementGeneration === historical.placementGeneration &&
    current.sandboxGeneration === historical.sandboxGeneration &&
    authorizationRotationIsMonotonicAndNonWidening(current, historical)
  );
}

function authorityCanSettleLease(
  authority: WorkspaceAuthoritySnapshot,
  lease: WorkspaceWriteLease,
): boolean {
  return (
    stableSettlementIdentityMatches(authority, lease.admissionAuthority) &&
    authority.tenantId === lease.tenantId &&
    authority.userId === lease.userId &&
    authority.sessionId === lease.sessionId &&
    authority.turnId === lease.turnId &&
    authority.effectId === lease.effectId &&
    authority.invocationId === lease.invocationId &&
    authority.requestDigest === lease.requestDigest &&
    authority.dispatchAttempt === lease.dispatchAttempt &&
    authority.sandboxId === lease.sandboxId &&
    authority.backend === lease.backend &&
    authority.turnLeaseGeneration === lease.turnLeaseGeneration &&
    authority.placementGeneration === lease.placementGeneration &&
    authority.sandboxGeneration === lease.sandboxGeneration &&
    authorizationRotationIsMonotonicAndNonWidening(authority, lease.admissionAuthority)
  );
}

function authorityMatchesLease(
  authority: WorkspaceAuthoritySnapshot,
  lease: WorkspaceWriteLease,
): boolean {
  return (
    authorityIdentityMatches(authority, lease.admissionAuthority) &&
    authority.tenantId === lease.tenantId &&
    authority.userId === lease.userId &&
    authority.sessionId === lease.sessionId &&
    authority.turnId === lease.turnId &&
    authority.effectId === lease.effectId &&
    authority.invocationId === lease.invocationId &&
    authority.requestDigest === lease.requestDigest &&
    authority.dispatchAttempt === lease.dispatchAttempt &&
    authority.sandboxId === lease.sandboxId &&
    authority.backend === lease.backend &&
    authority.turnLeaseGeneration === lease.turnLeaseGeneration &&
    authority.placementGeneration === lease.placementGeneration &&
    authority.sandboxGeneration === lease.sandboxGeneration &&
    authority.authorizationGeneration === lease.authorizationGeneration
  );
}

function acquireMatchesLease(
  command: AcquireWriteLeaseCommand,
  authority: WorkspaceAuthoritySnapshot,
  lease: WorkspaceWriteLease,
): boolean {
  return (
    authorityMatchesLease(authority, lease) &&
    authorityIdentityMatches(authority, lease.admissionAuthority) &&
    command.requestedLeaseId === lease.leaseId &&
    command.sandboxId === lease.sandboxId &&
    command.backend === lease.backend &&
    command.projectionGeneration === lease.projectionGeneration &&
    command.requestedLeaseTtlMs === lease.requestedLeaseTtlMs &&
    command.requestedMaximumHoldMs === lease.requestedMaximumHoldMs &&
    command.acquireDeadline === lease.acquireDeadline &&
    command.waitPolicy === lease.waitPolicy
  );
}

function acquireMatchesQueue(
  command: AcquireWriteLeaseCommand,
  authority: WorkspaceAuthoritySnapshot,
  queued: WorkspaceLeaseQueueEntry,
): boolean {
  const existing = queued.authority;
  return (
    authorityCanRefreshQueuedAdmission(authority, existing) &&
    queued.requestedLeaseId === command.requestedLeaseId &&
    queued.sandboxId === command.sandboxId &&
    queued.backend === command.backend &&
    queued.projectionGeneration === command.projectionGeneration &&
    queued.requestedLeaseTtlMs === command.requestedLeaseTtlMs &&
    queued.requestedMaximumHoldMs === command.requestedMaximumHoldMs &&
    queued.acquireDeadline === command.acquireDeadline &&
    queued.waitPolicy === command.waitPolicy
  );
}

function acquireMatchesConflict(
  command: AcquireWriteLeaseCommand,
  authority: WorkspaceAuthoritySnapshot,
  conflict: WorkspaceLeaseConflictRecord,
): boolean {
  return (
    stableSettlementIdentityMatches(authority, conflict.authority) &&
    command.requestedLeaseId === conflict.requestedLeaseId &&
    command.sandboxId === conflict.sandboxId &&
    command.backend === conflict.backend &&
    command.projectionGeneration === conflict.projectionGeneration &&
    command.requestedLeaseTtlMs === conflict.requestedLeaseTtlMs &&
    command.requestedMaximumHoldMs === conflict.requestedMaximumHoldMs &&
    command.acquireDeadline === conflict.acquireDeadline &&
    command.waitPolicy === conflict.waitPolicy
  );
}

function latestDispatchAttemptForInvocation(
  state: WorkspaceAggregateState,
  invocationId: string,
): number | null {
  const historyAttempt = state.leaseHistory.find(
    (record) => record.invocationId === invocationId,
  )?.latestDispatchAttempt;
  let latest = historyAttempt ?? null;
  for (const conflict of state.leaseConflicts) {
    if (
      conflict.invocationId === invocationId &&
      (latest === null || conflict.dispatchAttempt > latest)
    ) {
      latest = conflict.dispatchAttempt;
    }
  }
  return latest;
}

function validatedAcquireInputs(
  command: AcquireWriteLeaseCommand,
  state: WorkspaceAggregateState,
): WorkspaceAuthoritySnapshot {
  const authority = validatedAuthority(
    command.authority,
    state,
    "authority",
    command.now,
    "workspace.write",
    "admission",
  );
  validatedIdentifier(command.requestedLeaseId, "requestedLeaseId");
  validatedIdentifier(command.sandboxId, "sandboxId");
  validatedBackend(command.backend, "backend");
  if (authority.sandboxId !== command.sandboxId || authority.backend !== command.backend) {
    workspaceError("PERMISSION_DENIED", "authority sandbox scope does not match the request");
  }
  validatedInteger(command.projectionGeneration, "projectionGeneration", 0);
  const ttl = validatedInteger(command.requestedLeaseTtlMs, "requestedLeaseTtlMs", 1);
  const maximumHold = validatedInteger(
    command.requestedMaximumHoldMs,
    "requestedMaximumHoldMs",
    1,
  );
  if (maximumHold < ttl) {
    workspaceError(
      "INVALID_ARGUMENT",
      "requestedMaximumHoldMs must be greater than or equal to requestedLeaseTtlMs",
    );
  }
  validatedInteger(command.acquireDeadline, "acquireDeadline", 1);
  if (command.waitPolicy !== "queue" && command.waitPolicy !== "fail") {
    workspaceError("INVALID_ARGUMENT", "waitPolicy must be queue or fail");
  }
  checkedAdd(command.now, ttl, "initial lease expiry");
  checkedAdd(command.now, maximumHold, "maximum hold deadline");
  return authority;
}

function validatedFence(fence: WorkspaceLeaseFence, field = "leaseFence"): void {
  const record = validatedExactKeys(
    fence,
    [
      "leaseId",
      "invocationId",
      "requestDigest",
      "effectId",
      "sessionId",
      "sandboxId",
      "leaseGeneration",
      "dispatchAttempt",
      "turnLeaseGeneration",
      "placementGeneration",
      "sandboxGeneration",
      "projectionGeneration",
      "authorizationGeneration",
    ],
    field,
  );
  validatedIdentifier(record.leaseId, `${field}.leaseId`);
  validatedIdentifier(record.invocationId, `${field}.invocationId`);
  parseDigest(record.requestDigest, `${field}.requestDigest`);
  validatedIdentifier(record.effectId, `${field}.effectId`);
  validatedIdentifier(record.sessionId, `${field}.sessionId`);
  validatedIdentifier(record.sandboxId, `${field}.sandboxId`);
  validatedInteger(record.leaseGeneration, `${field}.leaseGeneration`, 1);
  validatedInteger(record.dispatchAttempt, `${field}.dispatchAttempt`, 1);
  validatedInteger(record.turnLeaseGeneration, `${field}.turnLeaseGeneration`, 0);
  validatedInteger(record.placementGeneration, `${field}.placementGeneration`, 0);
  validatedInteger(record.sandboxGeneration, `${field}.sandboxGeneration`, 0);
  validatedInteger(record.projectionGeneration, `${field}.projectionGeneration`, 0);
  validatedInteger(record.authorizationGeneration, `${field}.authorizationGeneration`, 0);
}

function currentLeaseForFence(
  state: WorkspaceAggregateState,
  fence: WorkspaceLeaseFence,
): WorkspaceWriteLease {
  validatedFence(fence);
  const lease = state.activeWriteLease;
  if (lease === null) {
    workspaceError("NOT_FOUND", "there is no active workspace write lease");
  }
  if (
    lease.invocationId === fence.invocationId &&
    lease.requestDigest !== fence.requestDigest
  ) {
    workspaceError(
      "IDEMPOTENCY_CONFLICT",
      `invocationId ${fence.invocationId} was reused with a different request digest`,
    );
  }
  if (
    lease.invocationId !== fence.invocationId ||
    lease.requestDigest !== fence.requestDigest ||
    lease.effectId !== fence.effectId ||
    lease.sessionId !== fence.sessionId
  ) {
    workspaceError("NOT_FOUND", "the lease fence does not identify the active invocation");
  }
  if (
    !fencesEqual(
      {
        leaseId: lease.leaseId,
        invocationId: lease.invocationId,
        requestDigest: lease.requestDigest,
        effectId: lease.effectId,
        sessionId: lease.sessionId,
        sandboxId: lease.sandboxId,
        leaseGeneration: lease.leaseGeneration,
        dispatchAttempt: lease.dispatchAttempt,
        turnLeaseGeneration: lease.turnLeaseGeneration,
        placementGeneration: lease.placementGeneration,
        sandboxGeneration: lease.sandboxGeneration,
        projectionGeneration: lease.projectionGeneration,
        authorizationGeneration: lease.authorizationGeneration,
      },
      fence,
    )
  ) {
    workspaceError("STALE_GENERATION", "the workspace lease fence is stale");
  }
  return lease;
}

function leaseHistoryIndex(
  state: WorkspaceAggregateState,
  invocationId: string,
): number {
  return state.leaseHistory.findIndex((record) => record.invocationId === invocationId);
}

function setLeaseHistory(
  state: WorkspaceAggregateState,
  record: WorkspaceLeaseHistoryRecord,
): void {
  const index = leaseHistoryIndex(state, record.invocationId);
  if (index === -1) {
    state.leaseHistory.push(record);
  } else {
    state.leaseHistory[index] = record;
  }
}

function dropWriteTicketsForLease(state: WorkspaceAggregateState, leaseId: string): void {
  state.materializationTickets = state.materializationTickets.filter(
    (ticket) => ticket.accessMode === "read_only" || ticket.leaseId !== leaseId,
  );
}

function grantQueueHead(
  state: WorkspaceAggregateState,
  queued: WorkspaceLeaseQueueEntry,
  now: number,
): WorkspaceWriteLease {
  const authority = queued.authority;
  const maximumHoldDeadline = checkedAdd(
    now,
    queued.requestedMaximumHoldMs,
    "maximum hold deadline",
  );
  const expiresAt = Math.min(
    checkedAdd(now, queued.requestedLeaseTtlMs, "initial lease expiry"),
    maximumHoldDeadline,
    authority.turnLeaseExpiresAt,
  );
  const lease: WorkspaceWriteLease = {
    leaseId: queued.requestedLeaseId,
    workspaceId: state.workspaceId,
    tenantId: authority.tenantId,
    userId: authority.userId,
    invocationId: authority.invocationId,
    requestDigest: authority.requestDigest,
    effectId: authority.effectId,
    sessionId: authority.sessionId,
    turnId: authority.turnId,
    sandboxId: queued.sandboxId,
    backend: queued.backend,
    baseRevision: state.revision,
    leaseGeneration: state.nextLeaseGeneration,
    dispatchAttempt: authority.dispatchAttempt,
    turnLeaseGeneration: authority.turnLeaseGeneration,
    placementGeneration: authority.placementGeneration,
    sandboxGeneration: authority.sandboxGeneration,
    projectionGeneration: queued.projectionGeneration,
    authorizationGeneration: authority.authorizationGeneration,
    admissionAuthority: authority,
    requestedLeaseTtlMs: queued.requestedLeaseTtlMs,
    requestedMaximumHoldMs: queued.requestedMaximumHoldMs,
    acquireDeadline: queued.acquireDeadline,
    waitPolicy: queued.waitPolicy,
    issuedAt: now,
    expiresAt,
    maximumHoldDeadline,
    renewalSequence: 0,
    enqueueSequence: queued.enqueueSequence,
    lastRenewal: null,
  };
  state.nextLeaseGeneration += 1;
  state.activeWriteLease = lease;
  setLeaseHistory(state, {
    invocationId: lease.invocationId,
    requestDigest: lease.requestDigest,
    latestProjectionGeneration: lease.projectionGeneration,
    latestDispatchAttempt: lease.dispatchAttempt,
    latestLeaseGeneration: lease.leaseGeneration,
    latestEnqueueSequence: lease.enqueueSequence,
    status: "active",
  });
  return lease;
}

function advanceLeaseQueue(
  state: WorkspaceAggregateState,
  now: number,
): { readonly changed: boolean; readonly promotedInvocationId: string | null } {
  let changed = false;
  if (state.activeWriteLease !== null && now >= state.activeWriteLease.expiresAt) {
    const expired = state.activeWriteLease;
    setLeaseHistory(state, {
      invocationId: expired.invocationId,
      requestDigest: expired.requestDigest,
      latestProjectionGeneration: expired.projectionGeneration,
      latestDispatchAttempt: expired.dispatchAttempt,
      latestLeaseGeneration: expired.leaseGeneration,
      latestEnqueueSequence: expired.enqueueSequence,
      status: "expired",
    });
    dropWriteTicketsForLease(state, expired.leaseId);
    state.activeWriteLease = null;
    changed = true;
  }

  while (state.writeQueue[0]?.canceled === true) {
    const canceled = state.writeQueue.shift();
    if (canceled === undefined) {
      break;
    }
    setLeaseHistory(state, {
      invocationId: canceled.authority.invocationId,
      requestDigest: canceled.authority.requestDigest,
      latestProjectionGeneration: canceled.projectionGeneration,
      latestDispatchAttempt: canceled.authority.dispatchAttempt,
      latestLeaseGeneration:
        state.leaseHistory.find(
          (history) => history.invocationId === canceled.authority.invocationId,
        )?.latestLeaseGeneration ?? null,
      latestEnqueueSequence: canceled.enqueueSequence,
      status: "canceled",
    });
    changed = true;
  }
  while (
    state.writeQueue[0] !== undefined &&
    now >= state.writeQueue[0].acquireDeadline
  ) {
    const timedOut = state.writeQueue.shift();
    if (timedOut === undefined) {
      break;
    }
    setLeaseHistory(state, {
      invocationId: timedOut.authority.invocationId,
      requestDigest: timedOut.authority.requestDigest,
      latestProjectionGeneration: timedOut.projectionGeneration,
      latestDispatchAttempt: timedOut.authority.dispatchAttempt,
      latestLeaseGeneration:
        state.leaseHistory.find(
          (history) => history.invocationId === timedOut.authority.invocationId,
        )?.latestLeaseGeneration ?? null,
      latestEnqueueSequence: timedOut.enqueueSequence,
      status: "timed_out",
    });
    changed = true;
    while (state.writeQueue[0]?.canceled === true) {
      const canceled = state.writeQueue.shift();
      if (canceled === undefined) {
        break;
      }
      setLeaseHistory(state, {
        invocationId: canceled.authority.invocationId,
        requestDigest: canceled.authority.requestDigest,
        latestProjectionGeneration: canceled.projectionGeneration,
        latestDispatchAttempt: canceled.authority.dispatchAttempt,
        latestLeaseGeneration:
          state.leaseHistory.find(
            (history) => history.invocationId === canceled.authority.invocationId,
          )?.latestLeaseGeneration ?? null,
        latestEnqueueSequence: canceled.enqueueSequence,
        status: "canceled",
      });
      changed = true;
    }
  }

  return { changed, promotedInvocationId: null };
}

function queuePosition(state: WorkspaceAggregateState, enqueueSequence: number): number {
  const position = state.writeQueue.findIndex(
    (entry) => entry.enqueueSequence === enqueueSequence,
  );
  if (position === -1) {
    workspaceError("FAILED_PRECONDITION", "queued lease admission disappeared");
  }
  return position + 1;
}

function committedResult(
  state: WorkspaceAggregateState,
  next: WorkspaceAggregateState,
  outcome: WorkspaceCommandOutcome,
  commandDigest: Digest,
): ApplyWorkspaceCommandResult {
  next.eventSequence = state.eventSequence + 1;
  assertWorkspaceInvariants(next);
  return { state: next, outcome: structuredClone(outcome), commandDigest, replayed: false };
}

function noMutationResult(
  state: WorkspaceAggregateState,
  outcome: WorkspaceCommandOutcome,
  commandDigest: Digest,
  replayed: boolean,
): ApplyWorkspaceCommandResult {
  return { state, outcome: structuredClone(outcome), commandDigest, replayed };
}

function invocationRecord(
  state: WorkspaceAggregateState,
  invocationId: string,
): WorkspaceInvocationRecord | undefined {
  return state.invocationLedger.find((record) => record.invocationId === invocationId);
}

function assertSortedProtectionPermitIds(values: readonly string[]): string[] {
  if (!Array.isArray(values)) {
    workspaceError("INVALID_ARGUMENT", "pendingProtectionPermitIds must be an array");
  }
  const result = values.map((value, index) =>
    validatedIdentifier(value, `pendingProtectionPermitIds[${index}]`),
  );
  for (let index = 1; index < result.length; index += 1) {
    const previous = result[index - 1];
    const current = result[index];
    if (previous === undefined || current === undefined) {
      workspaceError("INVALID_ARGUMENT", "pendingProtectionPermitIds is sparse");
    }
    if (compareUtf8(previous, current) >= 0) {
      workspaceError(
        "INVALID_ARGUMENT",
        "pendingProtectionPermitIds must be a unique UTF-8-sorted set",
      );
    }
  }
  return result;
}

function validatedReferencedObjectDigests(
  values: readonly Digest[],
  rootDigest: Digest,
  field = "referencedObjectDigests",
): Digest[] {
  if (!Array.isArray(values) || values.length === 0) {
    workspaceError("FAILED_PRECONDITION", `${field} must declare the complete root closure`);
  }
  const result = values.map((value, index) => parseDigest(value, `${field}[${index}]`));
  for (let index = 1; index < result.length; index += 1) {
    const previous = result[index - 1];
    const current = result[index];
    if (previous === undefined || current === undefined || compareUtf8(previous, current) >= 0) {
      workspaceError("INVALID_ARGUMENT", `${field} must be a unique UTF-8-sorted set`);
    }
  }
  if (!result.includes(rootDigest)) {
    workspaceError("FAILED_PRECONDITION", `${field} does not include the new root digest`);
  }
  return result;
}

function validatedProtectionProofs(
  values: readonly WorkspaceProtectionProof[],
  state: WorkspaceAggregateState,
  referencedObjectDigests: readonly Digest[],
): WorkspaceProtectionProof[] {
  if (!Array.isArray(values) || values.length === 0) {
    workspaceError("FAILED_PRECONDITION", "a new root requires GC protection proofs");
  }
  const result = values.map((value, index) => {
    const record = validatedExactKeys(
      value,
      ["permitId", "tenantId", "objectDigest", "guardGeneration", "status"],
      `protectionProofs[${index}]`,
    );
    const permitId = validatedIdentifier(record.permitId, `protectionProofs[${index}].permitId`);
    const tenantId = validatedIdentifier(record.tenantId, `protectionProofs[${index}].tenantId`);
    const objectDigest = parseDigest(
      record.objectDigest,
      `protectionProofs[${index}].objectDigest`,
    );
    const guardGeneration = validatedInteger(
      record.guardGeneration,
      `protectionProofs[${index}].guardGeneration`,
      1,
    );
    if (record.status !== "protected") {
      workspaceError("FAILED_PRECONDITION", "GC protection proof is not protected");
    }
    if (tenantId !== state.tenantId) {
      workspaceError("PERMISSION_DENIED", "GC protection proof belongs to another tenant");
    }
    return { permitId, tenantId, objectDigest, guardGeneration, status: "protected" } as const;
  });
  for (let index = 1; index < result.length; index += 1) {
    if (compareUtf8(result[index - 1]?.permitId ?? "", result[index]?.permitId ?? "") >= 0) {
      workspaceError(
        "INVALID_ARGUMENT",
        "protectionProofs must be a unique permit-ID-sorted set",
      );
    }
  }
  const objectDigests = new Set<string>();
  for (const proof of result) {
    if (objectDigests.has(proof.objectDigest)) {
      workspaceError("INVALID_ARGUMENT", "protectionProofs contains a duplicate object digest");
    }
    objectDigests.add(proof.objectDigest);
  }
  if (
    objectDigests.size !== referencedObjectDigests.length ||
    referencedObjectDigests.some((digest) => !objectDigests.has(digest))
  ) {
    workspaceError(
      "FAILED_PRECONDITION",
      "GC protection proofs do not exactly cover the declared root closure",
    );
  }
  return result;
}

function protectionProofsEqual(
  left: readonly WorkspaceProtectionProof[],
  right: readonly WorkspaceProtectionProof[],
): boolean {
  return (
    left.length === right.length &&
    left.every(
      (proof, index) =>
        proof.permitId === right[index]?.permitId &&
        proof.tenantId === right[index]?.tenantId &&
        proof.objectDigest === right[index]?.objectDigest &&
        proof.guardGeneration === right[index]?.guardGeneration &&
        proof.status === right[index]?.status,
    )
  );
}

function fencesEqual(left: WorkspaceLeaseFence, right: WorkspaceLeaseFence): boolean {
  return (
    left.leaseId === right.leaseId &&
    left.invocationId === right.invocationId &&
    left.requestDigest === right.requestDigest &&
    left.effectId === right.effectId &&
    left.sessionId === right.sessionId &&
    left.sandboxId === right.sandboxId &&
    left.leaseGeneration === right.leaseGeneration &&
    left.dispatchAttempt === right.dispatchAttempt &&
    left.turnLeaseGeneration === right.turnLeaseGeneration &&
    left.placementGeneration === right.placementGeneration &&
    left.sandboxGeneration === right.sandboxGeneration &&
    left.projectionGeneration === right.projectionGeneration &&
    left.authorizationGeneration === right.authorizationGeneration
  );
}

function authorityCanSettleFence(
  authority: WorkspaceAuthoritySnapshot,
  fence: WorkspaceLeaseFence,
): boolean {
  return (
    authority.invocationId === fence.invocationId &&
    authority.requestDigest === fence.requestDigest &&
    authority.effectId === fence.effectId &&
    authority.sessionId === fence.sessionId &&
    authority.sandboxId === fence.sandboxId &&
    authority.dispatchAttempt === fence.dispatchAttempt &&
    authority.turnLeaseGeneration === fence.turnLeaseGeneration &&
    authority.placementGeneration === fence.placementGeneration &&
    authority.sandboxGeneration === fence.sandboxGeneration &&
    authority.authorizationGeneration >= fence.authorizationGeneration
  );
}

function authorityMatchesTicket(
  authority: WorkspaceAuthoritySnapshot,
  ticket: WorkspaceMaterializationTicket,
): boolean {
  return (
    authorityIdentityMatches(authority, ticket.admissionAuthority) &&
    authority.tenantId === ticket.tenantId &&
    authority.userId === ticket.userId &&
    authority.invocationId === ticket.invocationId &&
    authority.requestDigest === ticket.requestDigest &&
    authority.effectId === ticket.effectId &&
    authority.sessionId === ticket.sessionId &&
    authority.turnId === ticket.turnId &&
    authority.sandboxId === ticket.sandboxId &&
    authority.backend === ticket.backend &&
    authority.dispatchAttempt === ticket.dispatchAttempt &&
    authority.turnLeaseGeneration === ticket.turnLeaseGeneration &&
    authority.placementGeneration === ticket.placementGeneration &&
    authority.sandboxGeneration === ticket.sandboxGeneration &&
    authority.authorizationGeneration === ticket.authorizationGeneration
  );
}

export function createWorkspaceState(
  input: CreateWorkspaceStateInput,
): WorkspaceAggregateState {
  validatedExactKeys(
    input,
    ["workspaceId", "tenantId", "initialRootDigest"],
    "create workspace input",
  );
  const initialRootDigest = parseDigest(input.initialRootDigest, "initialRootDigest");
  const state: WorkspaceAggregateState = {
    schemaVersion: WORKSPACE_STATE_SCHEMA_VERSION,
    workspaceId: validatedIdentifier(input.workspaceId, "workspaceId"),
    tenantId: validatedIdentifier(input.tenantId, "tenantId"),
    eventSequence: 0,
    revision: 0,
    rootDigest: initialRootDigest,
    revisions: [
      {
        revision: 0,
        parentRevision: null,
        rootDigest: initialRootDigest,
        workspaceCommitId: null,
        invocationId: null,
        requestDigest: null,
        referencedObjectDigests: [initialRootDigest],
        pendingProtectionPermitIds: [],
        committedAt: null,
      },
    ],
    nextLeaseGeneration: 1,
    nextLeaseEnqueueSequence: 0,
    activeWriteLease: null,
    writeQueue: [],
    leaseHistory: [],
    leaseConflicts: [],
    materializationTickets: [],
    knownLeaseIds: [],
    knownMaterializationTicketIds: [],
    invocationLedger: [],
  };
  assertWorkspaceInvariants(state);
  return state;
}

export function assertWorkspaceInvariants(state: WorkspaceAggregateState): void {
  try {
    normalizeProtocolValue(state);
  } catch (error) {
    if (error instanceof ProtocolValidationError) {
      workspaceError("INVALID_ARGUMENT", `workspace state is not serializable: ${error.message}`);
    }
    throw error;
  }
  validatedExactKeys(
    state,
    [
      "schemaVersion",
      "workspaceId",
      "tenantId",
      "eventSequence",
      "revision",
      "rootDigest",
      "revisions",
      "nextLeaseGeneration",
      "nextLeaseEnqueueSequence",
      "activeWriteLease",
      "writeQueue",
      "leaseHistory",
      "leaseConflicts",
      "materializationTickets",
      "knownLeaseIds",
      "knownMaterializationTicketIds",
      "invocationLedger",
    ],
    "state",
  );
  if (state.schemaVersion !== WORKSPACE_STATE_SCHEMA_VERSION) {
    workspaceError("FAILED_PRECONDITION", "unsupported workspace state schemaVersion");
  }
  validatedIdentifier(state.workspaceId, "state.workspaceId");
  validatedIdentifier(state.tenantId, "state.tenantId");
  validatedInteger(state.eventSequence, "state.eventSequence", 0);
  validatedInteger(state.revision, "state.revision", 0);
  parseDigest(state.rootDigest, "state.rootDigest");
  validatedInteger(state.nextLeaseGeneration, "state.nextLeaseGeneration", 1);
  validatedInteger(
    state.nextLeaseEnqueueSequence,
    "state.nextLeaseEnqueueSequence",
    0,
  );
  for (const [field, value] of [
    ["revisions", state.revisions],
    ["writeQueue", state.writeQueue],
    ["leaseHistory", state.leaseHistory],
    ["leaseConflicts", state.leaseConflicts],
    ["materializationTickets", state.materializationTickets],
    ["knownLeaseIds", state.knownLeaseIds],
    ["knownMaterializationTicketIds", state.knownMaterializationTicketIds],
    ["invocationLedger", state.invocationLedger],
  ] as const) {
    if (!Array.isArray(value)) {
      workspaceError("INVALID_ARGUMENT", `state.${field} must be an array`);
    }
  }

  if (state.revisions.length !== state.revision + 1) {
    workspaceError("FAILED_PRECONDITION", "revision history is not contiguous");
  }
  for (const [index, revision] of state.revisions.entries()) {
    validatedExactKeys(
      revision,
      [
        "revision",
        "parentRevision",
        "rootDigest",
        "workspaceCommitId",
        "invocationId",
        "requestDigest",
        "referencedObjectDigests",
        "pendingProtectionPermitIds",
        "committedAt",
      ],
      `state.revisions[${index}]`,
    );
    if (revision.revision !== index || revision.parentRevision !== (index === 0 ? null : index - 1)) {
      workspaceError("FAILED_PRECONDITION", "revision ancestry is not immutable and contiguous");
    }
    parseDigest(revision.rootDigest, `state.revisions[${index}].rootDigest`);
    validatedReferencedObjectDigests(
      revision.referencedObjectDigests,
      revision.rootDigest,
      `state.revisions[${index}].referencedObjectDigests`,
    );
    assertSortedProtectionPermitIds(revision.pendingProtectionPermitIds);
    if (index === 0) {
      if (
        revision.workspaceCommitId !== null ||
        revision.invocationId !== null ||
        revision.requestDigest !== null ||
        revision.committedAt !== null ||
        revision.referencedObjectDigests.length !== 1 ||
        revision.referencedObjectDigests[0] !== revision.rootDigest ||
        revision.pendingProtectionPermitIds.length !== 0
      ) {
        workspaceError("FAILED_PRECONDITION", "genesis revision has mutation metadata");
      }
    } else {
      validatedIdentifier(revision.workspaceCommitId, "revision.workspaceCommitId");
      validatedIdentifier(revision.invocationId, "revision.invocationId");
      parseDigest(revision.requestDigest, "revision.requestDigest");
      validatedInteger(revision.committedAt, "revision.committedAt", 0);
    }
  }
  if (state.revisions[state.revision]?.rootDigest !== state.rootDigest) {
    workspaceError("FAILED_PRECONDITION", "current root does not match the current revision");
  }

  const knownLeaseIds = new Set<string>();
  for (const leaseId of state.knownLeaseIds) {
    const validated = validatedIdentifier(leaseId, "state.knownLeaseIds[]");
    if (knownLeaseIds.has(validated)) {
      workspaceError("FAILED_PRECONDITION", "known lease ID was duplicated");
    }
    knownLeaseIds.add(validated);
  }

  let maximumLeaseGeneration = 0;
  let maximumEnqueueSequence = -1;
  if (state.activeWriteLease !== null) {
    const lease = state.activeWriteLease;
    validatedExactKeys(
      lease,
      [
        "leaseId",
        "workspaceId",
        "tenantId",
        "userId",
        "invocationId",
        "requestDigest",
        "effectId",
        "sessionId",
        "turnId",
        "sandboxId",
        "backend",
        "baseRevision",
        "leaseGeneration",
        "dispatchAttempt",
        "turnLeaseGeneration",
        "placementGeneration",
        "sandboxGeneration",
        "projectionGeneration",
        "authorizationGeneration",
        "admissionAuthority",
        "requestedLeaseTtlMs",
        "requestedMaximumHoldMs",
        "acquireDeadline",
        "waitPolicy",
        "issuedAt",
        "expiresAt",
        "maximumHoldDeadline",
        "renewalSequence",
        "enqueueSequence",
        "lastRenewal",
      ],
      "active lease",
    );
    if (!knownLeaseIds.has(lease.leaseId)) {
      workspaceError("FAILED_PRECONDITION", "active lease ID is not reserved");
    }
    if (lease.workspaceId !== state.workspaceId || lease.tenantId !== state.tenantId) {
      workspaceError("FAILED_PRECONDITION", "active lease belongs to another workspace");
    }
    const admissionAuthority = validatedAuthority(
      lease.admissionAuthority,
      state,
      "active lease admission authority",
      null,
      "workspace.write",
      "admission",
    );
    if (!authorityMatchesLease(admissionAuthority, lease)) {
      workspaceError("FAILED_PRECONDITION", "active lease admission authority is inconsistent");
    }
    parseDigest(lease.requestDigest, "active lease requestDigest");
    validatedIdentifier(lease.leaseId, "active lease leaseId");
    validatedIdentifier(lease.userId, "active lease userId");
    validatedIdentifier(lease.invocationId, "active lease invocationId");
    validatedIdentifier(lease.effectId, "active lease effectId");
    validatedIdentifier(lease.sessionId, "active lease sessionId");
    validatedIdentifier(lease.turnId, "active lease turnId");
    validatedIdentifier(lease.sandboxId, "active lease sandboxId");
    validatedBackend(lease.backend, "active lease backend");
    validatedInteger(lease.baseRevision, "active lease baseRevision", 0);
    validatedInteger(lease.leaseGeneration, "active lease generation", 1);
    validatedInteger(lease.dispatchAttempt, "active lease dispatchAttempt", 1);
    validatedInteger(lease.turnLeaseGeneration, "active lease turnLeaseGeneration", 0);
    validatedInteger(lease.placementGeneration, "active lease placementGeneration", 0);
    validatedInteger(lease.sandboxGeneration, "active lease sandboxGeneration", 0);
    validatedInteger(lease.projectionGeneration, "active lease projectionGeneration", 0);
    validatedInteger(
      lease.authorizationGeneration,
      "active lease authorizationGeneration",
      0,
    );
    validatedInteger(lease.enqueueSequence, "active lease enqueueSequence", 0);
    const requestedLeaseTtlMs = validatedInteger(
      lease.requestedLeaseTtlMs,
      "active lease requestedLeaseTtlMs",
      1,
    );
    const requestedMaximumHoldMs = validatedInteger(
      lease.requestedMaximumHoldMs,
      "active lease requestedMaximumHoldMs",
      1,
    );
    const issuedAt = validatedInteger(lease.issuedAt, "active lease issuedAt", 0);
    const expiresAt = validatedInteger(lease.expiresAt, "active lease expiresAt", 1);
    const maximumHoldDeadline = validatedInteger(
      lease.maximumHoldDeadline,
      "active lease maximumHoldDeadline",
      1,
    );
    validatedInteger(lease.acquireDeadline, "active lease acquireDeadline", 1);
    validatedInteger(lease.renewalSequence, "active lease renewalSequence", 0);
    if (
      requestedMaximumHoldMs < requestedLeaseTtlMs ||
      (lease.waitPolicy !== "queue" && lease.waitPolicy !== "fail") ||
      issuedAt >= expiresAt ||
      expiresAt > maximumHoldDeadline ||
      expiresAt > admissionAuthority.turnLeaseExpiresAt ||
      maximumHoldDeadline !==
        checkedAdd(issuedAt, requestedMaximumHoldMs, "active lease maximum hold deadline") ||
      lease.acquireDeadline <= issuedAt
    ) {
      workspaceError("FAILED_PRECONDITION", "active lease time bounds are invalid");
    }
    if (lease.baseRevision !== state.revision) {
      workspaceError("FAILED_PRECONDITION", "active lease base revision is not current");
    }
    if (lease.lastRenewal !== null) {
      const receipt = validatedExactKeys(
        lease.lastRenewal,
        ["renewalSequence", "requestedLeaseTtlMs", "expiresAt"],
        "active lease renewal receipt",
      );
      validatedInteger(
        receipt.renewalSequence,
        "active lease renewal receipt sequence",
        1,
      );
      validatedInteger(
        receipt.requestedLeaseTtlMs,
        "active lease renewal receipt requestedLeaseTtlMs",
        1,
      );
      validatedInteger(receipt.expiresAt, "active lease renewal receipt expiresAt", 1);
    }
    if (
      (lease.renewalSequence === 0) !== (lease.lastRenewal === null) ||
      (lease.lastRenewal !== null &&
        (lease.lastRenewal.renewalSequence !== lease.renewalSequence ||
          lease.lastRenewal.expiresAt !== lease.expiresAt))
    ) {
      workspaceError("FAILED_PRECONDITION", "active lease renewal receipt is inconsistent");
    }
    maximumLeaseGeneration = lease.leaseGeneration;
    maximumEnqueueSequence = lease.enqueueSequence;
  }

  const queuedInvocations = new Set<string>();
  let previousEnqueueSequence = -1;
  for (const entry of state.writeQueue) {
    validatedExactKeys(
      entry,
      [
        "authority",
        "requestedLeaseId",
        "sandboxId",
        "backend",
        "projectionGeneration",
        "requestedLeaseTtlMs",
        "requestedMaximumHoldMs",
        "acquireDeadline",
        "waitPolicy",
        "enqueueSequence",
        "canceled",
      ],
      "queued lease",
    );
    const authority = validatedAuthority(
      entry.authority,
      state,
      "queued authority",
      null,
      "workspace.write",
      "admission",
    );
    if (queuedInvocations.has(authority.invocationId)) {
      workspaceError("FAILED_PRECONDITION", "an invocation appears twice in the lease queue");
    }
    queuedInvocations.add(authority.invocationId);
    validatedIdentifier(entry.requestedLeaseId, "queued requestedLeaseId");
    validatedIdentifier(entry.sandboxId, "queued sandboxId");
    validatedBackend(entry.backend, "queued backend");
    validatedInteger(entry.projectionGeneration, "queued projectionGeneration", 0);
    validatedInteger(entry.requestedLeaseTtlMs, "queued requestedLeaseTtlMs", 1);
    validatedInteger(entry.requestedMaximumHoldMs, "queued requestedMaximumHoldMs", 1);
    validatedInteger(entry.acquireDeadline, "queued acquireDeadline", 1);
    validatedInteger(entry.enqueueSequence, "queued enqueueSequence", 0);
    if (
      entry.requestedMaximumHoldMs < entry.requestedLeaseTtlMs ||
      (entry.waitPolicy !== "queue" && entry.waitPolicy !== "fail") ||
      typeof entry.canceled !== "boolean" ||
      authority.sandboxId !== entry.sandboxId ||
      authority.backend !== entry.backend
    ) {
      workspaceError("FAILED_PRECONDITION", "queued lease admission is invalid");
    }
    if (state.activeWriteLease?.invocationId === authority.invocationId) {
      workspaceError("FAILED_PRECONDITION", "the active lease owner is also queued");
    }
    if (entry.enqueueSequence <= previousEnqueueSequence) {
      workspaceError("FAILED_PRECONDITION", "lease queue is not strict FIFO");
    }
    previousEnqueueSequence = entry.enqueueSequence;
    maximumEnqueueSequence = Math.max(maximumEnqueueSequence, entry.enqueueSequence);
    if (!knownLeaseIds.has(entry.requestedLeaseId)) {
      workspaceError("FAILED_PRECONDITION", "queued lease ID is not reserved");
    }
  }

  const historyInvocations = new Set<string>();
  const leaseHistoryByInvocation = new Map<string, WorkspaceLeaseHistoryRecord>();
  for (const history of state.leaseHistory) {
    validatedExactKeys(
      history,
      [
        "invocationId",
        "requestDigest",
        "latestProjectionGeneration",
        "latestDispatchAttempt",
        "latestLeaseGeneration",
        "latestEnqueueSequence",
        "status",
      ],
      "lease history",
    );
    if (historyInvocations.has(history.invocationId)) {
      workspaceError("FAILED_PRECONDITION", "lease history contains a duplicate invocation");
    }
    historyInvocations.add(history.invocationId);
    validatedIdentifier(history.invocationId, "lease history invocationId");
    parseDigest(history.requestDigest, "lease history requestDigest");
    validatedInteger(
      history.latestProjectionGeneration,
      "lease history projection generation",
      0,
    );
    validatedInteger(history.latestDispatchAttempt, "lease history dispatch attempt", 1);
    validatedInteger(history.latestEnqueueSequence, "lease history enqueue sequence", 0);
    maximumEnqueueSequence = Math.max(
      maximumEnqueueSequence,
      history.latestEnqueueSequence,
    );
    if (history.latestLeaseGeneration !== null) {
      validatedInteger(history.latestLeaseGeneration, "lease history generation", 1);
      maximumLeaseGeneration = Math.max(
        maximumLeaseGeneration,
        history.latestLeaseGeneration,
      );
    }
    if (
      history.status !== "queued" &&
      history.status !== "active" &&
      history.status !== "canceled" &&
      history.status !== "timed_out" &&
      history.status !== "expired" &&
      history.status !== "released" &&
      history.status !== "committed"
    ) {
      workspaceError("FAILED_PRECONDITION", "lease history status is invalid");
    }
    leaseHistoryByInvocation.set(history.invocationId, history);
  }
  if (state.nextLeaseGeneration <= maximumLeaseGeneration) {
    workspaceError("FAILED_PRECONDITION", "next lease generation is not monotonic");
  }
  if (state.nextLeaseEnqueueSequence <= maximumEnqueueSequence) {
    workspaceError("FAILED_PRECONDITION", "next lease enqueue sequence is not monotonic");
  }
  if (state.activeWriteLease !== null) {
    const activeHistory = leaseHistoryByInvocation.get(state.activeWriteLease.invocationId);
    if (
      activeHistory === undefined ||
      activeHistory.status !== "active" ||
      activeHistory.requestDigest !== state.activeWriteLease.requestDigest ||
      activeHistory.latestLeaseGeneration !== state.activeWriteLease.leaseGeneration ||
      activeHistory.latestDispatchAttempt !== state.activeWriteLease.dispatchAttempt ||
      activeHistory.latestEnqueueSequence !== state.activeWriteLease.enqueueSequence ||
      activeHistory.latestProjectionGeneration !==
        state.activeWriteLease.projectionGeneration
    ) {
      workspaceError("FAILED_PRECONDITION", "active lease history is inconsistent");
    }
  }
  for (const queued of state.writeQueue) {
    const history = leaseHistoryByInvocation.get(queued.authority.invocationId);
    if (
      history === undefined ||
      history.status !== (queued.canceled ? "canceled" : "queued") ||
      history.requestDigest !== queued.authority.requestDigest ||
      history.latestDispatchAttempt !== queued.authority.dispatchAttempt ||
      history.latestProjectionGeneration !== queued.projectionGeneration ||
      history.latestEnqueueSequence !== queued.enqueueSequence
    ) {
      workspaceError("FAILED_PRECONDITION", "queued lease history is inconsistent");
    }
  }

  const conflictAttempts = new Set<string>();
  const conflictDigests = new Map<string, Digest>();
  for (const conflict of state.leaseConflicts) {
    validatedExactKeys(
      conflict,
      [
        "invocationId",
        "requestDigest",
        "dispatchAttempt",
        "authority",
        "requestedLeaseId",
        "sandboxId",
        "backend",
        "projectionGeneration",
        "requestedLeaseTtlMs",
        "requestedMaximumHoldMs",
        "acquireDeadline",
        "waitPolicy",
        "recordedAt",
        "outcome",
      ],
      "lease conflict",
    );
    const invocationId = validatedIdentifier(
      conflict.invocationId,
      "lease conflict invocationId",
    );
    const requestDigest = parseDigest(conflict.requestDigest, "lease conflict requestDigest");
    const dispatchAttempt = validatedInteger(
      conflict.dispatchAttempt,
      "lease conflict dispatchAttempt",
      1,
    );
    const conflictKey = `${invocationId}\u0000${dispatchAttempt}`;
    if (conflictAttempts.has(conflictKey)) {
      workspaceError("FAILED_PRECONDITION", "lease conflict receipt was duplicated");
    }
    conflictAttempts.add(conflictKey);
    const priorDigest = conflictDigests.get(invocationId);
    if (priorDigest !== undefined && priorDigest !== requestDigest) {
      workspaceError("FAILED_PRECONDITION", "lease conflict invocation changed request digest");
    }
    conflictDigests.set(invocationId, requestDigest);
    const history = leaseHistoryByInvocation.get(invocationId);
    if (history !== undefined && history.requestDigest !== requestDigest) {
      workspaceError("FAILED_PRECONDITION", "lease conflict disagrees with lease history");
    }
    const recordedAt = validatedInteger(conflict.recordedAt, "lease conflict recordedAt", 0);
    const authority = validatedAuthority(
      conflict.authority,
      state,
      "lease conflict authority",
      recordedAt,
      "workspace.write",
      "admission",
    );
    validatedIdentifier(conflict.requestedLeaseId, "lease conflict requestedLeaseId");
    validatedIdentifier(conflict.sandboxId, "lease conflict sandboxId");
    validatedBackend(conflict.backend, "lease conflict backend");
    validatedInteger(conflict.projectionGeneration, "lease conflict projectionGeneration", 0);
    const requestedLeaseTtlMs = validatedInteger(
      conflict.requestedLeaseTtlMs,
      "lease conflict requestedLeaseTtlMs",
      1,
    );
    const requestedMaximumHoldMs = validatedInteger(
      conflict.requestedMaximumHoldMs,
      "lease conflict requestedMaximumHoldMs",
      1,
    );
    const acquireDeadline = validatedInteger(
      conflict.acquireDeadline,
      "lease conflict acquireDeadline",
      1,
    );
    validatedExactKeys(
      conflict.outcome,
      ["kind", "holderSessionId", "leaseGeneration", "expiresAt"],
      "lease conflict outcome",
    );
    if (
      conflict.waitPolicy !== "fail" ||
      conflict.outcome.kind !== "write_lease_conflict" ||
      authority.invocationId !== invocationId ||
      authority.requestDigest !== requestDigest ||
      authority.dispatchAttempt !== dispatchAttempt ||
      authority.sandboxId !== conflict.sandboxId ||
      authority.backend !== conflict.backend ||
      requestedMaximumHoldMs < requestedLeaseTtlMs ||
      acquireDeadline <= recordedAt
    ) {
      workspaceError("FAILED_PRECONDITION", "lease conflict receipt is inconsistent");
    }
    validatedIdentifier(conflict.outcome.holderSessionId, "lease conflict holderSessionId");
    validatedInteger(conflict.outcome.leaseGeneration, "lease conflict leaseGeneration", 0);
    if (
      validatedInteger(conflict.outcome.expiresAt, "lease conflict expiresAt", 1) <= recordedAt
    ) {
      workspaceError("FAILED_PRECONDITION", "lease conflict blocker was already expired");
    }
  }

  const knownTicketIds = new Set<string>();
  for (const ticketId of state.knownMaterializationTicketIds) {
    const validated = validatedIdentifier(ticketId, "known materialization ticket ID");
    if (knownTicketIds.has(validated)) {
      workspaceError("FAILED_PRECONDITION", "materialization ticket ID was reused");
    }
    knownTicketIds.add(validated);
  }
  const activeTicketIds = new Set<string>();
  for (const ticket of state.materializationTickets) {
    validatedExactKeys(
      ticket,
      [
        "ticketId",
        "accessMode",
        "workspaceId",
        "tenantId",
        "userId",
        "invocationId",
        "requestDigest",
        "effectId",
        "sessionId",
        "turnId",
        "sandboxId",
        "backend",
        "revision",
        "rootDigest",
        "leaseId",
        "leaseGeneration",
        "dispatchAttempt",
        "turnLeaseGeneration",
        "placementGeneration",
        "sandboxGeneration",
        "projectionGeneration",
        "authorizationGeneration",
        "issuedAt",
        "expiresAt",
        "requestedTicketTtlMs",
        "admissionAuthority",
      ],
      "materialization ticket",
    );
    if (!knownTicketIds.has(ticket.ticketId) || activeTicketIds.has(ticket.ticketId)) {
      workspaceError("FAILED_PRECONDITION", "materialization ticket identity is invalid");
    }
    activeTicketIds.add(ticket.ticketId);
    validatedIdentifier(ticket.ticketId, "materialization ticketId");
    validatedIdentifier(ticket.userId, "materialization userId");
    validatedIdentifier(ticket.invocationId, "materialization invocationId");
    parseDigest(ticket.requestDigest, "materialization requestDigest");
    validatedIdentifier(ticket.effectId, "materialization effectId");
    validatedIdentifier(ticket.sessionId, "materialization sessionId");
    validatedIdentifier(ticket.turnId, "materialization turnId");
    validatedIdentifier(ticket.sandboxId, "materialization sandboxId");
    validatedBackend(ticket.backend, "materialization backend");
    validatedInteger(ticket.revision, "materialization revision", 0);
    validatedInteger(ticket.dispatchAttempt, "materialization dispatchAttempt", 1);
    validatedInteger(ticket.turnLeaseGeneration, "materialization turnLeaseGeneration", 0);
    validatedInteger(ticket.placementGeneration, "materialization placementGeneration", 0);
    validatedInteger(ticket.sandboxGeneration, "materialization sandboxGeneration", 0);
    validatedInteger(ticket.projectionGeneration, "materialization projectionGeneration", 0);
    validatedInteger(
      ticket.authorizationGeneration,
      "materialization authorizationGeneration",
      0,
    );
    validatedInteger(ticket.issuedAt, "materialization issuedAt", 0);
    validatedInteger(ticket.expiresAt, "materialization expiresAt", 1);
    validatedInteger(
      ticket.requestedTicketTtlMs,
      "materialization requestedTicketTtlMs",
      1,
    );
    if (ticket.accessMode !== "read_only" && ticket.accessMode !== "read_write") {
      workspaceError("FAILED_PRECONDITION", "materialization access mode is invalid");
    }
    const ticketAuthority = validatedAuthority(
      ticket.admissionAuthority,
      state,
      "materialization admissionAuthority",
      null,
      ticket.accessMode === "read_write" ? "workspace.write" : "workspace.read",
      "admission",
    );
    if (!authorityMatchesTicket(ticketAuthority, ticket)) {
      workspaceError("FAILED_PRECONDITION", "materialization authority is inconsistent");
    }
    if (ticket.workspaceId !== state.workspaceId || ticket.tenantId !== state.tenantId) {
      workspaceError("FAILED_PRECONDITION", "materialization ticket scope is invalid");
    }
    const revision = state.revisions[ticket.revision];
    if (revision === undefined || revision.rootDigest !== ticket.rootDigest) {
      workspaceError("FAILED_PRECONDITION", "materialization ticket snapshot is not fixed");
    }
    if (
      ticket.issuedAt >= ticket.expiresAt ||
      ticket.expiresAt >
        checkedAdd(ticket.issuedAt, ticket.requestedTicketTtlMs, "materialization maximum expiry") ||
      ticket.expiresAt > ticketAuthority.turnLeaseExpiresAt
    ) {
      workspaceError("FAILED_PRECONDITION", "materialization ticket time bounds are invalid");
    }
    if (
      ticket.accessMode === "read_only" &&
      (ticket.leaseId !== null || ticket.leaseGeneration !== null)
    ) {
      workspaceError("FAILED_PRECONDITION", "read-only materialization joined writer authority");
    }
    if (
      ticket.accessMode === "read_write" &&
      (ticket.leaseId === null || ticket.leaseGeneration === null)
    ) {
      workspaceError("FAILED_PRECONDITION", "write materialization lacks lease fencing");
    }
    if (
      ticket.accessMode === "read_write" &&
      (state.activeWriteLease === null ||
        ticket.leaseId !== state.activeWriteLease.leaseId ||
        ticket.leaseGeneration !== state.activeWriteLease.leaseGeneration ||
        ticket.sandboxId !== state.activeWriteLease.sandboxId ||
        ticket.sandboxGeneration !== state.activeWriteLease.sandboxGeneration ||
        ticket.projectionGeneration !== state.activeWriteLease.projectionGeneration ||
        ticket.expiresAt > state.activeWriteLease.expiresAt)
    ) {
      workspaceError("FAILED_PRECONDITION", "write materialization is not actively fenced");
    }
  }

  const invocationIds = new Set<string>();
  const commitIds = new Set<string>();
  const invocationLedgerByRevision = new Map<number, WorkspaceInvocationRecord>();
  for (const record of state.invocationLedger) {
    validatedExactKeys(
      record,
      [
        "invocationId",
        "requestDigest",
        "baseRevision",
        "status",
        "result",
        "referencedObjectDigests",
        "pendingProtectionPermitIds",
        "protectionProofs",
        "materializationTicketId",
        "leaseFence",
        "commitAuthority",
      ],
      "invocation ledger record",
    );
    validatedExactKeys(
      record.result,
      ["workspaceCommitId", "revision", "rootDigest"],
      "invocation ledger result",
    );
    if (invocationIds.has(record.invocationId) || commitIds.has(record.result.workspaceCommitId)) {
      workspaceError("FAILED_PRECONDITION", "workspace invocation ledger identity was reused");
    }
    invocationIds.add(record.invocationId);
    commitIds.add(record.result.workspaceCommitId);
    if (
      state.activeWriteLease?.invocationId === record.invocationId ||
      queuedInvocations.has(record.invocationId)
    ) {
      workspaceError("FAILED_PRECONDITION", "a committed invocation still has writer authority");
    }
    parseDigest(record.requestDigest, "invocation ledger requestDigest");
    validatedIdentifier(record.invocationId, "invocation ledger invocationId");
    validatedIdentifier(record.result.workspaceCommitId, "invocation ledger workspaceCommitId");
    const resultRevision = validatedInteger(
      record.result.revision,
      "invocation ledger revision",
      1,
    );
    parseDigest(record.result.rootDigest, "invocation ledger rootDigest");
    validatedInteger(record.baseRevision, "invocation ledger baseRevision", 0);
    validatedIdentifier(
      record.materializationTicketId,
      "invocation ledger materializationTicketId",
    );
    validatedFence(record.leaseFence, "invocation ledger leaseFence");
    const recordPermitIds = assertSortedProtectionPermitIds(
      record.pendingProtectionPermitIds,
    );
    const commitAuthority = validatedAuthority(
      record.commitAuthority,
      state,
      "invocation ledger commitAuthority",
      null,
      null,
      "settlement",
    );
    if (
      !authorityCanSettleFence(commitAuthority, record.leaseFence) ||
      commitAuthority.invocationId !== record.invocationId ||
      commitAuthority.requestDigest !== record.requestDigest
    ) {
      workspaceError("FAILED_PRECONDITION", "invocation ledger authority is inconsistent");
    }
    const revision = state.revisions[resultRevision];
    if (
      record.status !== "committed" ||
      revision === undefined ||
      revision.invocationId !== record.invocationId ||
      revision.requestDigest !== record.requestDigest ||
      revision.workspaceCommitId !== record.result.workspaceCommitId ||
      revision.rootDigest !== record.result.rootDigest ||
      record.baseRevision !== revision.parentRevision
    ) {
      workspaceError("FAILED_PRECONDITION", "invocation ledger result is not revision-backed");
    }
    const referencedObjectDigests = validatedReferencedObjectDigests(
      record.referencedObjectDigests,
      record.result.rootDigest,
      "invocation ledger referencedObjectDigests",
    );
    if (
      referencedObjectDigests.length !== revision.referencedObjectDigests.length ||
      referencedObjectDigests.some(
        (digest, index) => digest !== revision.referencedObjectDigests[index],
      )
    ) {
      workspaceError("FAILED_PRECONDITION", "invocation root closure does not match revision");
    }
    if (
      recordPermitIds.length !==
        revision.pendingProtectionPermitIds.length ||
      recordPermitIds.some(
        (permitId, index) => permitId !== revision.pendingProtectionPermitIds[index],
      )
    ) {
      workspaceError("FAILED_PRECONDITION", "invocation protection permits do not match revision");
    }
    const protectionProofs = validatedProtectionProofs(
      record.protectionProofs,
      state,
      referencedObjectDigests,
    );
    if (
      recordPermitIds.length !== protectionProofs.length ||
      recordPermitIds.some(
        (permitId, index) => permitId !== protectionProofs[index]?.permitId,
      ) ||
      !protectionProofsEqual(protectionProofs, record.protectionProofs)
    ) {
      workspaceError("FAILED_PRECONDITION", "invocation protection proof is inconsistent");
    }
    const committedHistory = leaseHistoryByInvocation.get(record.invocationId);
    if (
      committedHistory === undefined ||
      committedHistory.status !== "committed" ||
      committedHistory.requestDigest !== record.requestDigest ||
      committedHistory.latestDispatchAttempt !== record.leaseFence.dispatchAttempt ||
      committedHistory.latestLeaseGeneration !== record.leaseFence.leaseGeneration ||
      committedHistory.latestProjectionGeneration !== record.leaseFence.projectionGeneration
    ) {
      workspaceError("FAILED_PRECONDITION", "committed lease history is inconsistent");
    }
    invocationLedgerByRevision.set(resultRevision, record);
  }
  for (const revision of state.revisions.slice(1)) {
    const record = invocationLedgerByRevision.get(revision.revision);
    if (
      record === undefined ||
      record.invocationId !== revision.invocationId ||
      record.requestDigest !== revision.requestDigest ||
      record.result.workspaceCommitId !== revision.workspaceCommitId ||
      record.result.rootDigest !== revision.rootDigest ||
      record.referencedObjectDigests.length !== revision.referencedObjectDigests.length ||
      record.referencedObjectDigests.some(
        (digest, index) => digest !== revision.referencedObjectDigests[index],
      )
    ) {
      workspaceError("FAILED_PRECONDITION", "revision is missing its invocation ledger record");
    }
  }
  for (const history of state.leaseHistory) {
    if (
      history.status === "committed" &&
      !invocationIds.has(history.invocationId)
    ) {
      workspaceError("FAILED_PRECONDITION", "committed lease history lacks a ledger record");
    }
  }
}

export function lookupWorkspaceInvocation(
  state: WorkspaceAggregateState,
  invocationIdInput: string,
  requestDigestInput: Digest,
  authorityInput: WorkspaceAuthoritySnapshot,
  now: number,
): WorkspaceInvocationRecord | null {
  assertWorkspaceInvariants(state);
  validatedInteger(now, "now", 0);
  const authority = validatedAuthority(
    authorityInput,
    state,
    "authority",
    now,
    null,
    "settlement",
  );
  const invocationId = validatedIdentifier(invocationIdInput, "invocationId");
  const requestDigest = parseDigest(requestDigestInput, "requestDigest");
  if (authority.invocationId !== invocationId || authority.requestDigest !== requestDigest) {
    workspaceError("PERMISSION_DENIED", "settlement authority does not match the lookup target");
  }
  const record = invocationRecord(state, invocationId);
  if (record === undefined) {
    return null;
  }
  if (record.requestDigest !== requestDigest) {
    workspaceError(
      "IDEMPOTENCY_CONFLICT",
      `invocationId ${invocationId} was reused with a different request digest`,
    );
  }
  if (!stableSettlementIdentityMatches(authority, record.commitAuthority)) {
    workspaceError("STALE_GENERATION", "settlement authority is stale");
  }
  return structuredClone(record);
}

export async function applyWorkspaceCommand(
  state: WorkspaceAggregateState,
  command: WorkspaceCommand,
): Promise<ApplyWorkspaceCommandResult> {
  assertWorkspaceInvariants(state);
  const commandRecord = validatedDataRecord(command, "command");
  let commandFields: readonly string[];
  switch (commandRecord.kind) {
    case "acquire_write_lease":
      commandFields = [
        "kind",
        "expectedEventSequence",
        "now",
        "authority",
        "requestedLeaseId",
        "sandboxId",
        "backend",
        "projectionGeneration",
        "requestedLeaseTtlMs",
        "requestedMaximumHoldMs",
        "acquireDeadline",
        "waitPolicy",
      ];
      break;
    case "renew_write_lease":
      commandFields = [
        "kind",
        "expectedEventSequence",
        "now",
        "leaseFence",
        "nextRenewalSequence",
        "requestedLeaseTtlMs",
        "authority",
      ];
      break;
    case "release_write_lease":
      commandFields = ["kind", "expectedEventSequence", "now", "leaseFence", "authority"];
      break;
    case "cancel_write_lease_request":
      commandFields = [
        "kind",
        "expectedEventSequence",
        "now",
        "invocationId",
        "requestDigest",
        "authority",
      ];
      break;
    case "reconcile_write_queue":
      commandFields = ["kind", "expectedEventSequence", "now"];
      break;
    case "prepare_materialization":
      commandFields = [
        "kind",
        "expectedEventSequence",
        "now",
        "ticketId",
        "accessMode",
        "requestedRevision",
        "authority",
        "sandboxId",
        "backend",
        "projectionGeneration",
        "leaseFence",
        "ticketTtlMs",
      ];
      break;
    case "commit_workspace":
      commandFields = [
        "kind",
        "expectedEventSequence",
        "now",
        "materializationTicketId",
        "leaseFence",
        "baseRevision",
        "workspaceCommitId",
        "postExecutionRootDigest",
        "referencedObjectDigests",
        "protectionProofs",
        "authority",
      ];
      break;
    default:
      workspaceError("INVALID_ARGUMENT", "unknown workspace command kind");
  }
  validatedExactKeys(command, commandFields, "command");
  validatedInteger(command.expectedEventSequence, "expectedEventSequence", 0);
  validatedInteger(command.now, "now", 0);

  let commandDigest;
  try {
    commandDigest = await digestStructuredValue(
      "circulusd.state-app.workspace-command",
      WORKSPACE_COMMAND_SCHEMA_VERSION,
      command,
    );
  } catch (error) {
    if (error instanceof ProtocolValidationError) {
      workspaceError("INVALID_ARGUMENT", `command is not serializable: ${error.message}`);
    }
    throw error;
  }

  if (command.kind === "commit_workspace") {
    validatedFence(command.leaseFence);
    const authority = validatedAuthority(
      command.authority,
      state,
      "authority",
      command.now,
      null,
      "settlement",
    );
    const materializationTicketId = validatedIdentifier(
      command.materializationTicketId,
      "materializationTicketId",
    );
    const baseRevision = validatedInteger(command.baseRevision, "baseRevision", 0);
    const workspaceCommitId = validatedIdentifier(command.workspaceCommitId, "workspaceCommitId");
    const rootDigest = parseDigest(command.postExecutionRootDigest, "postExecutionRootDigest");
    const referencedObjectDigests = validatedReferencedObjectDigests(
      command.referencedObjectDigests,
      rootDigest,
    );
    const protectionProofs = validatedProtectionProofs(
      command.protectionProofs,
      state,
      referencedObjectDigests,
    );
    const prior = invocationRecord(state, command.leaseFence.invocationId);
    if (prior !== undefined) {
      if (prior.requestDigest !== command.leaseFence.requestDigest) {
        workspaceError(
          "IDEMPOTENCY_CONFLICT",
          `invocationId ${prior.invocationId} was reused with a different request digest`,
        );
      }
      if (
        !stableSettlementIdentityMatches(authority, prior.commitAuthority) ||
        !fencesEqual(command.leaseFence, prior.leaseFence)
      ) {
        workspaceError("STALE_GENERATION", "committed-ledger replay authority is stale");
      }
      if (
        materializationTicketId !== prior.materializationTicketId ||
        baseRevision !== prior.baseRevision ||
        workspaceCommitId !== prior.result.workspaceCommitId ||
        rootDigest !== prior.result.rootDigest ||
        referencedObjectDigests.length !== prior.referencedObjectDigests.length ||
        referencedObjectDigests.some(
          (digest, index) => digest !== prior.referencedObjectDigests[index],
        ) ||
        !protectionProofsEqual(protectionProofs, prior.protectionProofs)
      ) {
        workspaceError(
          "IDEMPOTENCY_CONFLICT",
          "committed workspace invocation was replayed with different inputs",
        );
      }
      return noMutationResult(
        state,
        { kind: "workspace_committed", result: prior.result },
        commandDigest,
        true,
      );
    }
    if (!authorityCanSettleFence(authority, command.leaseFence)) {
      workspaceError("STALE_GENERATION", "settlement authority does not match the lease fence");
    }
    if (authority.effectStatus === "externally_committed") {
      workspaceError(
        "FAILED_PRECONDITION",
        "externally committed authority requires an existing workspace ledger result",
      );
    }
  }

  if (command.kind === "acquire_write_lease") {
    const authority = validatedAcquireInputs(command, state);
    const history = state.leaseHistory.find(
      (record) => record.invocationId === authority.invocationId,
    );
    if (history !== undefined && history.requestDigest !== authority.requestDigest) {
      workspaceError(
        "IDEMPOTENCY_CONFLICT",
        `invocationId ${authority.invocationId} was reused with a different request digest`,
      );
    }
    const conflicts = state.leaseConflicts.filter(
      (record) => record.invocationId === authority.invocationId,
    );
    if (conflicts.some((record) => record.requestDigest !== authority.requestDigest)) {
      workspaceError(
        "IDEMPOTENCY_CONFLICT",
        `invocationId ${authority.invocationId} was reused with a different request digest`,
      );
    }
    const conflict = conflicts.find(
      (record) => record.dispatchAttempt === authority.dispatchAttempt,
    );
    if (conflict !== undefined) {
      if (!acquireMatchesConflict(command, authority, conflict)) {
        workspaceError(
          "IDEMPOTENCY_CONFLICT",
          "fail-policy lease acquisition changed its durable receipt inputs",
        );
      }
      return noMutationResult(state, conflict.outcome, commandDigest, true);
    }
    const active = state.activeWriteLease;
    if (
      active !== null &&
      command.now < active.expiresAt &&
      active.invocationId === authority.invocationId
    ) {
      if (!authorityIdentityMatches(authority, active.admissionAuthority)) {
        workspaceError("STALE_GENERATION", "lease acquisition authority is stale");
      }
      if (!acquireMatchesLease(command, authority, active)) {
        workspaceError(
          "IDEMPOTENCY_CONFLICT",
          "idempotent lease acquisition changed its admission bounds",
        );
      }
      return noMutationResult(
        state,
        { kind: "write_lease_acquired", lease: active },
        commandDigest,
        true,
      );
    }
    const queued = state.writeQueue.find(
      (entry) => entry.authority.invocationId === authority.invocationId,
    );
    if (
      active !== null &&
      command.now < active.expiresAt &&
      queued !== undefined &&
      !queued.canceled &&
      command.now < queued.acquireDeadline
    ) {
      if (!authorityCanRefreshQueuedAdmission(authority, queued.authority)) {
        workspaceError("STALE_GENERATION", "queued lease acquisition authority is stale");
      }
      if (!acquireMatchesQueue(command, authority, queued)) {
        workspaceError(
          "IDEMPOTENCY_CONFLICT",
          "idempotent queued acquisition changed its admission bounds",
        );
      }
      return noMutationResult(
        state,
        {
          kind: "write_lease_queued",
          invocationId: authority.invocationId,
          enqueueSequence: queued.enqueueSequence,
          queuePosition: queuePosition(state, queued.enqueueSequence),
        },
        commandDigest,
        true,
      );
    }
  }

  if (command.kind === "renew_write_lease") {
    validatedInteger(command.nextRenewalSequence, "nextRenewalSequence", 1);
    validatedInteger(command.requestedLeaseTtlMs, "requestedLeaseTtlMs", 1);
    const active = currentLeaseForFence(state, command.leaseFence);
    const authority = validatedAuthority(
      command.authority,
      state,
      "authority",
      command.now,
      "workspace.write",
      "admission",
    );
    if (!authorityMatchesLease(authority, active)) {
      workspaceError("STALE_GENERATION", "lease renewal authority is stale");
    }
    if (command.now >= active.expiresAt) {
      workspaceError("LEASE_EXPIRED", "the workspace write lease has expired");
    }
    if (command.nextRenewalSequence === active.renewalSequence) {
      const receipt = active.lastRenewal;
      if (
        receipt === null ||
        receipt.renewalSequence !== command.nextRenewalSequence ||
        receipt.requestedLeaseTtlMs !== command.requestedLeaseTtlMs
      ) {
        workspaceError(
          "IDEMPOTENCY_CONFLICT",
          "renewal sequence was retried with a different request",
        );
      }
      return noMutationResult(
        state,
        {
          kind: "write_lease_renewed",
          leaseId: active.leaseId,
          renewalSequence: receipt.renewalSequence,
          expiresAt: receipt.expiresAt,
        },
        commandDigest,
        true,
      );
    }
  }

  if (command.kind === "prepare_materialization") {
    const ticketId = validatedIdentifier(command.ticketId, "ticketId");
    const existing = state.materializationTickets.find(
      (ticket) => ticket.ticketId === ticketId,
    );
    if (existing !== undefined) {
      if (command.accessMode !== "read_only" && command.accessMode !== "read_write") {
        workspaceError("INVALID_ARGUMENT", "accessMode must be read_only or read_write");
      }
      const authority = validatedAuthority(
        command.authority,
        state,
        "authority",
        command.now,
        command.accessMode === "read_write" ? "workspace.write" : "workspace.read",
        "admission",
      );
      const sandboxId = validatedIdentifier(command.sandboxId, "sandboxId");
      const backend = validatedBackend(command.backend, "backend");
      const requestedRevision = validatedInteger(
        command.requestedRevision,
        "requestedRevision",
        0,
      );
      const projectionGeneration = validatedInteger(
        command.projectionGeneration,
        "projectionGeneration",
        0,
      );
      const ticketTtlMs = validatedInteger(command.ticketTtlMs, "ticketTtlMs", 1);
      if (authority.sandboxId !== sandboxId || authority.backend !== backend) {
        workspaceError("PERMISSION_DENIED", "authority sandbox scope does not match the request");
      }
      if (command.leaseFence !== null) {
        validatedFence(command.leaseFence);
      }
      if (!authorityMatchesTicket(authority, existing)) {
        workspaceError("STALE_GENERATION", "materialization replay authority is stale");
      }
      let currentLease: WorkspaceWriteLease | null = null;
      if (existing.accessMode === "read_write" && command.leaseFence !== null) {
        currentLease = currentLeaseForFence(state, command.leaseFence);
        if (command.now >= currentLease.expiresAt) {
          workspaceError("LEASE_EXPIRED", "the workspace write lease has expired");
        }
        if (!authorityMatchesLease(authority, currentLease)) {
          workspaceError("STALE_GENERATION", "materialization authority is stale");
        }
      }
      if (
        existing.accessMode !== command.accessMode ||
        existing.revision !== requestedRevision ||
        existing.invocationId !== authority.invocationId ||
        existing.requestDigest !== authority.requestDigest ||
        existing.effectId !== authority.effectId ||
        existing.sessionId !== authority.sessionId ||
        existing.dispatchAttempt !== authority.dispatchAttempt ||
        existing.turnLeaseGeneration !== authority.turnLeaseGeneration ||
        existing.placementGeneration !== authority.placementGeneration ||
        existing.sandboxGeneration !== authority.sandboxGeneration ||
        existing.authorizationGeneration !== authority.authorizationGeneration ||
        existing.sandboxId !== sandboxId ||
        existing.backend !== backend ||
        existing.projectionGeneration !== projectionGeneration ||
        existing.requestedTicketTtlMs !== ticketTtlMs ||
        (existing.accessMode === "read_only" && command.leaseFence !== null) ||
        (existing.accessMode === "read_write" &&
          (command.leaseFence === null ||
            existing.leaseId !== command.leaseFence.leaseId ||
            existing.leaseGeneration !== command.leaseFence.leaseGeneration))
      ) {
        workspaceError(
          "IDEMPOTENCY_CONFLICT",
          `materialization ticket ${command.ticketId} was reused`,
        );
      }
      if (command.now >= existing.expiresAt) {
        workspaceError("LEASE_EXPIRED", "the materialization ticket has expired");
      }
      if (existing.accessMode === "read_write") {
        if (command.leaseFence === null) {
          workspaceError("FAILED_PRECONDITION", "write materialization requires a lease fence");
        }
        if (currentLease === null) {
          workspaceError("FAILED_PRECONDITION", "write materialization lease disappeared");
        }
      }
      return noMutationResult(
        state,
        { kind: "materialization_prepared", ticket: existing },
        commandDigest,
        true,
      );
    }
    if (state.knownMaterializationTicketIds.includes(command.ticketId)) {
      workspaceError("ALREADY_EXISTS", `materialization ticket ${command.ticketId} was consumed`);
    }
  }

  if (command.expectedEventSequence !== state.eventSequence) {
    workspaceError(
      "CONFLICT",
      `expected eventSequence ${command.expectedEventSequence}, current is ${state.eventSequence}`,
    );
  }

  const next = structuredClone(state);

  switch (command.kind) {
    case "acquire_write_lease": {
      const authority = validatedAcquireInputs(command, next);
      const advanced = advanceLeaseQueue(next, command.now);
      const history = next.leaseHistory.find(
        (record) => record.invocationId === authority.invocationId,
      );
      if (history !== undefined && history.requestDigest !== authority.requestDigest) {
        workspaceError(
          "IDEMPOTENCY_CONFLICT",
          `invocationId ${authority.invocationId} was reused with a different request digest`,
        );
      }
      if (history?.status === "committed") {
        workspaceError("ALREADY_EXISTS", `invocation ${authority.invocationId} already committed`);
      }

      const active = next.activeWriteLease;
      if (active?.invocationId === authority.invocationId) {
        if (!authorityIdentityMatches(authority, active.admissionAuthority)) {
          workspaceError("STALE_GENERATION", "promoted lease authority is stale");
        }
        if (!acquireMatchesLease(command, authority, active)) {
          workspaceError(
            "IDEMPOTENCY_CONFLICT",
            "promoted lease does not match the idempotent admission request",
          );
        }
        return committedResult(
          state,
          next,
          { kind: "write_lease_acquired", lease: active },
          commandDigest,
        );
      }

      const queued = next.writeQueue.find(
        (entry) => entry.authority.invocationId === authority.invocationId,
      );
      if (queued !== undefined) {
        if (queued.canceled || command.now >= queued.acquireDeadline) {
          workspaceError("FAILED_PRECONDITION", "the prior lease admission is no longer live");
        }
        if (!authorityCanRefreshQueuedAdmission(authority, queued.authority)) {
          workspaceError("STALE_GENERATION", "queued lease acquisition authority is stale");
        }
        if (!acquireMatchesQueue(command, authority, queued)) {
          workspaceError(
            "IDEMPOTENCY_CONFLICT",
            "idempotent queued acquisition changed its admission bounds",
          );
        }
        if (
          next.activeWriteLease === null &&
          next.writeQueue[0]?.enqueueSequence === queued.enqueueSequence
        ) {
          const refreshed: WorkspaceLeaseQueueEntry = { ...queued, authority };
          next.writeQueue[0] = refreshed;
          const removed = next.writeQueue.shift();
          if (removed?.enqueueSequence !== refreshed.enqueueSequence) {
            workspaceError("FAILED_PRECONDITION", "FIFO lease head changed during admission");
          }
          const granted = grantQueueHead(next, refreshed, command.now);
          return committedResult(
            state,
            next,
            { kind: "write_lease_acquired", lease: granted },
            commandDigest,
          );
        }
        const outcome: WorkspaceCommandOutcome = {
          kind: "write_lease_queued",
          invocationId: authority.invocationId,
          enqueueSequence: queued.enqueueSequence,
          queuePosition: queuePosition(next, queued.enqueueSequence),
        };
        return advanced.changed
          ? committedResult(state, next, outcome, commandDigest)
          : noMutationResult(state, outcome, commandDigest, true);
      }

      const latestDispatchAttempt = latestDispatchAttemptForInvocation(
        next,
        authority.invocationId,
      );
      if (
        latestDispatchAttempt !== null &&
        authority.dispatchAttempt !== latestDispatchAttempt + 1
      ) {
        workspaceError(
          "STALE_GENERATION",
          "terminal lease admission requires exactly the next dispatch attempt",
        );
      }
      if (
        history !== undefined &&
        history.latestLeaseGeneration !== null &&
        (history.status === "expired" || history.status === "released") &&
        command.projectionGeneration <= history.latestProjectionGeneration
      ) {
        workspaceError(
          "STALE_GENERATION",
          "lease reacquisition requires a newly materialized projection generation",
        );
      }
      if (next.knownLeaseIds.includes(command.requestedLeaseId)) {
        workspaceError("ALREADY_EXISTS", `lease ID ${command.requestedLeaseId} was already used`);
      }
      if (command.acquireDeadline <= command.now) {
        workspaceError("FAILED_PRECONDITION", "the lease acquire deadline has elapsed");
      }

      if (
        command.waitPolicy === "fail" &&
        (next.activeWriteLease !== null || next.writeQueue.length > 0)
      ) {
        const holder = next.activeWriteLease;
        const queuedHolder = next.writeQueue[0];
        let outcome: WorkspaceWriteLeaseConflictOutcome;
        if (holder !== null) {
          outcome = {
            kind: "write_lease_conflict",
            holderSessionId: holder.sessionId,
            leaseGeneration: holder.leaseGeneration,
            expiresAt: holder.expiresAt,
          };
        } else {
          if (queuedHolder === undefined) {
            workspaceError("FAILED_PRECONDITION", "FIFO conflict holder disappeared");
          }
          outcome = {
            kind: "write_lease_conflict",
            holderSessionId: queuedHolder.authority.sessionId,
            leaseGeneration: 0,
            expiresAt: queuedHolder.acquireDeadline,
          };
        }
        const receipt: WorkspaceLeaseConflictRecord = {
          invocationId: authority.invocationId,
          requestDigest: authority.requestDigest,
          dispatchAttempt: authority.dispatchAttempt,
          authority,
          requestedLeaseId: command.requestedLeaseId,
          sandboxId: command.sandboxId,
          backend: command.backend,
          projectionGeneration: command.projectionGeneration,
          requestedLeaseTtlMs: command.requestedLeaseTtlMs,
          requestedMaximumHoldMs: command.requestedMaximumHoldMs,
          acquireDeadline: command.acquireDeadline,
          waitPolicy: "fail",
          recordedAt: command.now,
          outcome,
        };
        next.leaseConflicts.push(receipt);
        return committedResult(state, next, outcome, commandDigest);
      }

      const enqueueSequence = next.nextLeaseEnqueueSequence;
      next.nextLeaseEnqueueSequence += 1;
      next.knownLeaseIds.push(command.requestedLeaseId);
      const entry: WorkspaceLeaseQueueEntry = {
        authority,
        requestedLeaseId: command.requestedLeaseId,
        sandboxId: command.sandboxId,
        backend: command.backend,
        projectionGeneration: command.projectionGeneration,
        requestedLeaseTtlMs: command.requestedLeaseTtlMs,
        requestedMaximumHoldMs: command.requestedMaximumHoldMs,
        acquireDeadline: command.acquireDeadline,
        waitPolicy: command.waitPolicy,
        enqueueSequence,
        canceled: false,
      };
      next.writeQueue.push(entry);
      setLeaseHistory(next, {
        invocationId: authority.invocationId,
        requestDigest: authority.requestDigest,
        latestProjectionGeneration: command.projectionGeneration,
        latestDispatchAttempt: authority.dispatchAttempt,
        latestLeaseGeneration: history?.latestLeaseGeneration ?? null,
        latestEnqueueSequence: enqueueSequence,
        status: "queued",
      });

      if (
        next.activeWriteLease === null &&
        next.writeQueue[0]?.enqueueSequence === enqueueSequence
      ) {
        const queuedHead = next.writeQueue.shift();
        if (queuedHead === undefined) {
          workspaceError("FAILED_PRECONDITION", "new FIFO head disappeared");
        }
        const granted = grantQueueHead(next, queuedHead, command.now);
        return committedResult(
          state,
          next,
          { kind: "write_lease_acquired", lease: granted },
          commandDigest,
        );
      }

      return committedResult(
        state,
        next,
        {
          kind: "write_lease_queued",
          invocationId: authority.invocationId,
          enqueueSequence,
          queuePosition: queuePosition(next, enqueueSequence),
        },
        commandDigest,
      );
    }

    case "renew_write_lease": {
      const lease = currentLeaseForFence(next, command.leaseFence);
      const authority = validatedAuthority(
        command.authority,
        next,
        "authority",
        command.now,
        "workspace.write",
        "admission",
      );
      if (!authorityMatchesLease(authority, lease)) {
        workspaceError("STALE_GENERATION", "lease renewal authority is stale");
      }
      if (command.now >= lease.expiresAt) {
        workspaceError("LEASE_EXPIRED", "the workspace write lease has expired");
      }
      if (command.nextRenewalSequence !== lease.renewalSequence + 1) {
        workspaceError(
          "STALE_GENERATION",
          `nextRenewalSequence must be exactly ${lease.renewalSequence + 1}`,
        );
      }
      const requestedExpiry = checkedAdd(
        command.now,
        command.requestedLeaseTtlMs,
        "renewed lease expiry",
      );
      const expiresAt = Math.min(
        authority.turnLeaseExpiresAt,
        Math.max(
          lease.expiresAt,
          Math.min(requestedExpiry, lease.maximumHoldDeadline),
        ),
      );
      const renewed: WorkspaceWriteLease = {
        ...lease,
        admissionAuthority: structuredClone(authority),
        expiresAt,
        renewalSequence: command.nextRenewalSequence,
        lastRenewal: {
          renewalSequence: command.nextRenewalSequence,
          requestedLeaseTtlMs: command.requestedLeaseTtlMs,
          expiresAt,
        },
      };
      next.activeWriteLease = renewed;
      next.materializationTickets = next.materializationTickets.map((ticket) => {
        if (ticket.accessMode !== "read_write" || ticket.leaseId !== renewed.leaseId) {
          return ticket;
        }
        const ticketMaximumExpiry = checkedAdd(
          ticket.issuedAt,
          ticket.requestedTicketTtlMs,
          "ticket expiry",
        );
        return {
          ...ticket,
          expiresAt: Math.min(ticketMaximumExpiry, renewed.expiresAt),
          admissionAuthority: structuredClone(authority),
        };
      });
      return committedResult(
        state,
        next,
        {
          kind: "write_lease_renewed",
          leaseId: renewed.leaseId,
          renewalSequence: renewed.renewalSequence,
          expiresAt: renewed.expiresAt,
        },
        commandDigest,
      );
    }

    case "release_write_lease": {
      const lease = currentLeaseForFence(next, command.leaseFence);
      const authority = validatedAuthority(
        command.authority,
        next,
        "authority",
        command.now,
        "workspace.write",
        "admission",
      );
      if (!authorityMatchesLease(authority, lease)) {
        workspaceError("STALE_GENERATION", "lease release authority is stale");
      }
      setLeaseHistory(next, {
        invocationId: lease.invocationId,
        requestDigest: lease.requestDigest,
        latestProjectionGeneration: lease.projectionGeneration,
        latestDispatchAttempt: lease.dispatchAttempt,
        latestLeaseGeneration: lease.leaseGeneration,
        latestEnqueueSequence: lease.enqueueSequence,
        status: "released",
      });
      dropWriteTicketsForLease(next, lease.leaseId);
      next.activeWriteLease = null;
      const advanced = advanceLeaseQueue(next, command.now);
      return committedResult(
        state,
        next,
        {
          kind: "write_lease_released",
          leaseId: lease.leaseId,
          promotedInvocationId: advanced.promotedInvocationId,
        },
        commandDigest,
      );
    }

    case "cancel_write_lease_request": {
      const invocationId = validatedIdentifier(command.invocationId, "invocationId");
      const requestDigest = parseDigest(command.requestDigest, "requestDigest");
      const authority = validatedAuthority(
        command.authority,
        next,
        "authority",
        command.now,
        "workspace.write",
        "admission",
      );
      if (
        authority.invocationId !== invocationId ||
        authority.requestDigest !== requestDigest
      ) {
        workspaceError("PERMISSION_DENIED", "cancel authority does not match the queued request");
      }
      const history = next.leaseHistory.find(
        (record) => record.invocationId === invocationId,
      );
      const index = next.writeQueue.findIndex(
        (entry) => entry.authority.invocationId === invocationId,
      );
      if (index === -1) {
        if (history !== undefined && history.requestDigest !== requestDigest) {
          workspaceError(
            "IDEMPOTENCY_CONFLICT",
            `invocationId ${invocationId} was reused with a different request digest`,
          );
        }
        workspaceError("NOT_FOUND", `queued invocation ${invocationId} was not found`);
      }
      const queued = next.writeQueue[index];
      if (queued === undefined) {
        workspaceError("NOT_FOUND", `queued invocation ${invocationId} was not found`);
      }
      if (queued.authority.requestDigest !== requestDigest) {
        workspaceError(
          "IDEMPOTENCY_CONFLICT",
          `invocationId ${invocationId} was reused with a different request digest`,
        );
      }
      if (!authorityIdentityMatches(authority, queued.authority)) {
        workspaceError("STALE_GENERATION", "cancel authority is stale");
      }
      next.writeQueue[index] = { ...queued, canceled: true };
      setLeaseHistory(next, {
        invocationId,
        requestDigest,
        latestProjectionGeneration: queued.projectionGeneration,
        latestDispatchAttempt: queued.authority.dispatchAttempt,
        latestLeaseGeneration: history?.latestLeaseGeneration ?? null,
        latestEnqueueSequence: queued.enqueueSequence,
        status: "canceled",
      });
      if (next.activeWriteLease === null) {
        advanceLeaseQueue(next, command.now);
      }
      return committedResult(
        state,
        next,
        {
          kind: "write_lease_request_canceled",
          invocationId,
          enqueueSequence: queued.enqueueSequence,
        },
        commandDigest,
      );
    }

    case "reconcile_write_queue": {
      const advanced = advanceLeaseQueue(next, command.now);
      const outcome: WorkspaceCommandOutcome = {
        kind: "write_queue_reconciled",
        promotedInvocationId: advanced.promotedInvocationId,
      };
      return advanced.changed
        ? committedResult(state, next, outcome, commandDigest)
        : noMutationResult(state, outcome, commandDigest, false);
    }

    case "prepare_materialization": {
      if (command.accessMode !== "read_only" && command.accessMode !== "read_write") {
        workspaceError("INVALID_ARGUMENT", "accessMode must be read_only or read_write");
      }
      const authority = validatedAuthority(
        command.authority,
        next,
        "authority",
        command.now,
        command.accessMode === "read_write" ? "workspace.write" : "workspace.read",
        "admission",
      );
      const ticketId = validatedIdentifier(command.ticketId, "ticketId");
      const sandboxId = validatedIdentifier(command.sandboxId, "sandboxId");
      const backend = validatedBackend(command.backend, "backend");
      if (authority.sandboxId !== sandboxId || authority.backend !== backend) {
        workspaceError("PERMISSION_DENIED", "authority sandbox scope does not match the request");
      }
      const requestedRevision = validatedInteger(
        command.requestedRevision,
        "requestedRevision",
        0,
      );
      const projectionGeneration = validatedInteger(
        command.projectionGeneration,
        "projectionGeneration",
        0,
      );
      const ticketTtlMs = validatedInteger(command.ticketTtlMs, "ticketTtlMs", 1);
      const revision = next.revisions[requestedRevision];
      if (revision === undefined) {
        workspaceError("NOT_FOUND", `workspace revision ${requestedRevision} was not found`);
      }
      let lease: WorkspaceWriteLease | null = null;
      if (command.accessMode === "read_only") {
        if (command.leaseFence !== null) {
          workspaceError("INVALID_ARGUMENT", "read-only materialization cannot carry a lease");
        }
      } else if (command.accessMode === "read_write") {
        if (command.leaseFence === null) {
          workspaceError("FAILED_PRECONDITION", "write materialization requires a lease fence");
        }
        lease = currentLeaseForFence(next, command.leaseFence);
        if (command.now >= lease.expiresAt) {
          workspaceError("LEASE_EXPIRED", "the workspace write lease has expired");
        }
        if (!authorityMatchesLease(authority, lease)) {
          workspaceError("STALE_GENERATION", "materialization authority is stale");
        }
        if (
          lease.sandboxId !== sandboxId ||
          lease.backend !== backend ||
          lease.projectionGeneration !== projectionGeneration
        ) {
          workspaceError("STALE_GENERATION", "materialization projection is stale");
        }
        if (requestedRevision !== lease.baseRevision) {
          workspaceError("CONFLICT", "materialization revision does not match the lease base");
        }
      }
      if (next.knownMaterializationTicketIds.includes(ticketId)) {
        workspaceError("ALREADY_EXISTS", `materialization ticket ${ticketId} was already used`);
      }
      const requestedExpiry = checkedAdd(command.now, ticketTtlMs, "ticket expiry");
      const expiresAt = Math.min(
        requestedExpiry,
        authority.turnLeaseExpiresAt,
        lease?.expiresAt ?? Number.MAX_SAFE_INTEGER,
      );
      if (expiresAt <= command.now) {
        workspaceError("LEASE_EXPIRED", "materialization ticket has no valid lifetime");
      }
      const ticket: WorkspaceMaterializationTicket = {
        ticketId,
        accessMode: command.accessMode,
        workspaceId: next.workspaceId,
        tenantId: authority.tenantId,
        userId: authority.userId,
        invocationId: authority.invocationId,
        requestDigest: authority.requestDigest,
        effectId: authority.effectId,
        sessionId: authority.sessionId,
        turnId: authority.turnId,
        sandboxId,
        backend,
        revision: requestedRevision,
        rootDigest: revision.rootDigest,
        leaseId: lease?.leaseId ?? null,
        leaseGeneration: lease?.leaseGeneration ?? null,
        dispatchAttempt: authority.dispatchAttempt,
        turnLeaseGeneration: authority.turnLeaseGeneration,
        placementGeneration: authority.placementGeneration,
        sandboxGeneration: authority.sandboxGeneration,
        projectionGeneration,
        authorizationGeneration: authority.authorizationGeneration,
        issuedAt: command.now,
        expiresAt,
        requestedTicketTtlMs: ticketTtlMs,
        admissionAuthority: authority,
      };
      next.knownMaterializationTicketIds.push(ticketId);
      next.materializationTickets.push(ticket);
      return committedResult(
        state,
        next,
        { kind: "materialization_prepared", ticket },
        commandDigest,
      );
    }

    case "commit_workspace": {
      const lease = currentLeaseForFence(next, command.leaseFence);
      const authority = validatedAuthority(
        command.authority,
        next,
        "authority",
        command.now,
        null,
        "settlement",
      );
      if (!authorityCanSettleLease(authority, lease)) {
        workspaceError("STALE_GENERATION", "workspace settlement authority is stale");
      }
      if (command.now >= lease.expiresAt) {
        workspaceError("LEASE_EXPIRED", "the workspace write lease has expired");
      }
      const ticketId = validatedIdentifier(
        command.materializationTicketId,
        "materializationTicketId",
      );
      const ticket = next.materializationTickets.find(
        (candidate) => candidate.ticketId === ticketId,
      );
      if (ticket === undefined) {
        workspaceError("NOT_FOUND", `materialization ticket ${ticketId} was not found`);
      }
      if (ticket.accessMode !== "read_write") {
        workspaceError("FAILED_PRECONDITION", "a read-only materialization cannot commit");
      }
      if (
        ticket.leaseId !== lease.leaseId ||
        ticket.leaseGeneration !== lease.leaseGeneration ||
        ticket.invocationId !== lease.invocationId ||
        ticket.requestDigest !== lease.requestDigest ||
        ticket.effectId !== lease.effectId ||
        ticket.sessionId !== lease.sessionId ||
        ticket.sandboxId !== lease.sandboxId ||
        ticket.backend !== lease.backend ||
        ticket.dispatchAttempt !== lease.dispatchAttempt ||
        ticket.turnLeaseGeneration !== lease.turnLeaseGeneration ||
        ticket.placementGeneration !== lease.placementGeneration ||
        ticket.sandboxGeneration !== lease.sandboxGeneration ||
        ticket.projectionGeneration !== lease.projectionGeneration ||
        ticket.authorizationGeneration !== lease.authorizationGeneration
      ) {
        workspaceError("STALE_GENERATION", "materialization ticket is stale");
      }
      const baseRevision = validatedInteger(command.baseRevision, "baseRevision", 0);
      if (
        baseRevision !== next.revision ||
        baseRevision !== lease.baseRevision ||
        baseRevision !== ticket.revision
      ) {
        workspaceError("CONFLICT", "workspace base revision is stale");
      }
      const workspaceCommitId = validatedIdentifier(
        command.workspaceCommitId,
        "workspaceCommitId",
      );
      if (
        next.revisions.some((revision) => revision.workspaceCommitId === workspaceCommitId)
      ) {
        workspaceError("ALREADY_EXISTS", `workspaceCommitId ${workspaceCommitId} was reused`);
      }
      const rootDigest = parseDigest(
        command.postExecutionRootDigest,
        "postExecutionRootDigest",
      );
      const referencedObjectDigests = validatedReferencedObjectDigests(
        command.referencedObjectDigests,
        rootDigest,
      );
      const protectionProofs = validatedProtectionProofs(
        command.protectionProofs,
        next,
        referencedObjectDigests,
      );
      const permitIds = assertSortedProtectionPermitIds(
        protectionProofs.map((proof) => proof.permitId),
      );
      const revisionNumber = next.revision + 1;
      const result = {
        workspaceCommitId,
        revision: revisionNumber,
        rootDigest,
      } as const;
      const revision: WorkspaceRevision = {
        revision: revisionNumber,
        parentRevision: baseRevision,
        rootDigest,
        workspaceCommitId,
        invocationId: lease.invocationId,
        requestDigest: lease.requestDigest,
        referencedObjectDigests: [...referencedObjectDigests],
        pendingProtectionPermitIds: [...permitIds],
        committedAt: command.now,
      };
      const ledger: WorkspaceInvocationRecord = {
        invocationId: lease.invocationId,
        requestDigest: lease.requestDigest,
        baseRevision,
        status: "committed",
        result: structuredClone(result),
        referencedObjectDigests: [...referencedObjectDigests],
        pendingProtectionPermitIds: [...permitIds],
        protectionProofs: structuredClone(protectionProofs),
        materializationTicketId: ticketId,
        leaseFence: structuredClone(command.leaseFence),
        commitAuthority: structuredClone(authority),
      };

      next.revision = revisionNumber;
      next.rootDigest = rootDigest;
      next.revisions.push(revision);
      next.invocationLedger.push(ledger);
      dropWriteTicketsForLease(next, lease.leaseId);
      setLeaseHistory(next, {
        invocationId: lease.invocationId,
        requestDigest: lease.requestDigest,
        latestProjectionGeneration: lease.projectionGeneration,
        latestDispatchAttempt: lease.dispatchAttempt,
        latestLeaseGeneration: lease.leaseGeneration,
        latestEnqueueSequence: lease.enqueueSequence,
        status: "committed",
      });
      next.activeWriteLease = null;
      advanceLeaseQueue(next, command.now);
      return committedResult(
        state,
        next,
        { kind: "workspace_committed", result },
        commandDigest,
      );
    }
  }
}
