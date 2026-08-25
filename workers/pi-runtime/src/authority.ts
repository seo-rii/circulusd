import { PiRuntimeError } from "./errors.ts";

const MAX_AUTHORITY_BYTES = 4_096;

export class OpaqueTurnAuthority {
  readonly #token: Uint8Array;

  constructor(token: Uint8Array) {
    if (
      !(token instanceof Uint8Array) ||
      Object.getPrototypeOf(token) !== Uint8Array.prototype ||
      token.byteLength === 0 ||
      token.byteLength > MAX_AUTHORITY_BYTES
    ) {
      throw new PiRuntimeError(
        "INVALID_CONTEXT",
        `turn authority must contain 1..${MAX_AUTHORITY_BYTES} opaque bytes`,
      );
    }
    this.#token = new Uint8Array(token);
    Object.freeze(this);
  }

  toString(): string {
    return "[OpaqueTurnAuthority REDACTED]";
  }

  toJSON(): string {
    return "[OpaqueTurnAuthority REDACTED]";
  }

  isPresent(): boolean {
    return this.#token.byteLength > 0;
  }
}

export function createOpaqueTurnAuthority(token: Uint8Array): OpaqueTurnAuthority {
  return new OpaqueTurnAuthority(token);
}
