export type SessionAggregateErrorCode =
  | "INVALID_ARGUMENT"
  | "PERMISSION_DENIED"
  | "NOT_FOUND"
  | "ALREADY_EXISTS"
  | "CONFLICT"
  | "IDEMPOTENCY_CONFLICT"
  | "FAILED_PRECONDITION"
  | "STALE_GENERATION"
  | "STALE_DISPATCH_ATTEMPT"
  | "DISPATCH_ALREADY_STARTED"
  | "DIGEST_MISMATCH"
  | "NEEDS_CONFIRMATION"
  | "ABORTED";

export class SessionAggregateError extends Error {
  readonly code: SessionAggregateErrorCode;

  constructor(code: SessionAggregateErrorCode, message: string) {
    super(message);
    this.name = "SessionAggregateError";
    this.code = code;
  }
}

export function sessionError(code: SessionAggregateErrorCode, message: string): never {
  throw new SessionAggregateError(code, message);
}
