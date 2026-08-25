export type PiRuntimeErrorCode =
  | "INVALID_CONFIGURATION"
  | "INVALID_CONTEXT"
  | "INVALID_CHECKPOINT"
  | "CHECKPOINT_IDENTITY_MISMATCH"
  | "SETTLEMENT_REQUIRED"
  | "UNEXPECTED_SETTLEMENT"
  | "SETTLEMENT_MISMATCH"
  | "STEP_IN_PROGRESS"
  | "ENGINE_TERMINAL"
  | "ENGINE_POISONED"
  | "HOOK_REGISTRY_FROZEN"
  | "INITIALIZATION_FAILED"
  | "TOOL_NAME_COLLISION";

export class PiRuntimeError extends Error {
  readonly code: PiRuntimeErrorCode;

  constructor(code: PiRuntimeErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "PiRuntimeError";
    this.code = code;
  }
}

export type BoundaryFaultCode =
  | "CORE_OUTPUT_INVALID"
  | "CORE_EXECUTION_FAILED"
  | "EXTENSION_OUTPUT_INVALID"
  | "EXTENSION_HOOK_FAILED"
  | "EVENT_BUDGET_EXCEEDED"
  | "STEP_TIMEOUT"
  | "TURN_ABORTED";

export class BoundaryFault extends Error {
  readonly code: BoundaryFaultCode;

  constructor(code: BoundaryFaultCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "BoundaryFault";
    this.code = code;
  }
}
