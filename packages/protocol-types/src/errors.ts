export class ProtocolValidationError extends Error {
  readonly path: string;

  constructor(path: string, message: string) {
    super(`${path}: ${message}`);
    this.name = "ProtocolValidationError";
    this.path = path;
  }
}

export function validationError(path: string, message: string): never {
  throw new ProtocolValidationError(path, message);
}
