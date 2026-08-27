import type {
  CreateCapabilityGenerationStateInput,
  CreateExtensionStateInput,
} from "../control/index.ts";

function namedCell(kind: string, identity: readonly (string | number)[]): string {
  return JSON.stringify(["circulusd.state-app.cell", 1, kind, ...identity]);
}

export function sessionCellName(tenantId: string, sessionId: string): string {
  return namedCell("session", [tenantId, sessionId]);
}

export function workspaceCellName(tenantId: string, workspaceId: string): string {
  return namedCell("workspace", [tenantId, workspaceId]);
}

export function userCellName(tenantId: string, userId: string): string {
  return namedCell("user", [tenantId, userId]);
}

export function extensionStateCellName(initialization: CreateExtensionStateInput): string {
  return namedCell("extension-state", [
    initialization.tenantId,
    initialization.scopeKind,
    initialization.scopeId,
    initialization.extensionId,
    initialization.extensionSchemaVersion,
    initialization.stateGeneration,
  ]);
}

export function capabilityGenerationCellName(
  initialization: CreateCapabilityGenerationStateInput,
): string {
  return namedCell("capability-generation", [
    initialization.tenantId,
    initialization.subjectKind,
    initialization.subjectId,
    initialization.generationKind,
  ]);
}

export function auditCellName(tenantId: string): string {
  return namedCell("audit", [tenantId]);
}
