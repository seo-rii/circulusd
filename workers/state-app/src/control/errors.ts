export type ControlAggregateErrorCode =
  | "INVALID_ARGUMENT"
  | "CONFLICT"
  | "IDEMPOTENCY_CONFLICT"
  | "PERMISSION_DENIED"
  | "STALE_GENERATION"
  | "RESOURCE_EXHAUSTED"
  | "FAILED_PRECONDITION";

export class ControlAggregateError extends Error {
  readonly code: ControlAggregateErrorCode;

  constructor(code: ControlAggregateErrorCode, message: string) {
    super(message);
    this.name = "ControlAggregateError";
    this.code = code;
  }
}

export function controlError(
  code: ControlAggregateErrorCode,
  message: string,
): never {
  throw new ControlAggregateError(code, message);
}
