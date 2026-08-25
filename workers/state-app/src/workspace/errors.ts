export type WorkspaceAggregateErrorCode =
  | "INVALID_ARGUMENT"
  | "NOT_FOUND"
  | "ALREADY_EXISTS"
  | "CONFLICT"
  | "IDEMPOTENCY_CONFLICT"
  | "PERMISSION_DENIED"
  | "FAILED_PRECONDITION"
  | "STALE_GENERATION"
  | "LEASE_EXPIRED";

export class WorkspaceAggregateError extends Error {
  readonly code: WorkspaceAggregateErrorCode;

  constructor(code: WorkspaceAggregateErrorCode, message: string) {
    super(message);
    this.name = "WorkspaceAggregateError";
    this.code = code;
  }
}

export function workspaceError(
  code: WorkspaceAggregateErrorCode,
  message: string,
): never {
  throw new WorkspaceAggregateError(code, message);
}
