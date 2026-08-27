import {
  PROTOCOL_MAJOR,
  PROTOCOL_MINOR,
  PROTOCOL_NAME,
  ProtocolValidationError,
  normalizeProtocolValue,
  parseRpcEnvelope,
  type Digest,
  type RpcEnvelope,
  type ValueParser,
} from "@circulusd/protocol-types";

import type { ControlAggregateErrorCode } from "../control/errors.ts";
import type { SessionAggregateErrorCode } from "../session/errors.ts";
import type { WorkspaceAggregateErrorCode } from "../workspace/errors.ts";
import type { HostContractErrorCode } from "./contracts.ts";

const MEBIBYTE = 1_048_576;
const ENVELOPE_HEADROOM_BYTES = 65_536;
const STANDARD_MAX_DEPTH = 72;
const STANDARD_MAX_ITEMS = 100_000;

export const HOST_RPC_OPERATIONS = Object.freeze([
  "session.initialize",
  "session.execute",
  "session.read",
  "session.read-events",
  "workspace.initialize",
  "workspace.execute",
  "workspace.lookup-invocation",
  "user.initialize",
  "user.execute",
  "user.read",
  "extension-state.initialize",
  "extension-state.execute",
  "extension-state.read",
  "capability-generation.initialize",
  "capability-generation.execute",
  "capability-generation.assert-current",
  "audit.initialize",
  "audit.execute",
  "audit.read",
] as const);

export type HostRpcOperation = (typeof HOST_RPC_OPERATIONS)[number];

export interface HostRpcContract {
  readonly schemaDigest: Digest;
  readonly requestMaxEncodedBytes: number;
  readonly requestMaxDepth: number;
  readonly requestMaxItems: number;
  readonly responseMaxEncodedBytes: number;
  readonly responseMaxDepth: number;
  readonly responseMaxItems: number;
}

type HostRpcSizeContract = Omit<
  HostRpcContract,
  "requestMaxItems" | "responseMaxItems"
>;

// These literals are generated from the actual request, response, validation,
// and error-framing sources by scripts/generate-rpc-digests.mjs. The golden
// test fails whenever those sources change without an intentional wire-identity
// rotation; production dispatch never accepts a caller-selected digest.
const HOST_RPC_SIZE_CONTRACTS: Readonly<
  Record<HostRpcOperation, HostRpcSizeContract>
> =
  Object.freeze({
    "session.initialize": Object.freeze({
      schemaDigest:
        "sha256:8b8c637fe16c5a3e59ccb32e14ed44450c21d6ba0b7af4630eaa2215dc4c819d",
      requestMaxEncodedBytes: 2 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "session.execute": Object.freeze({
      schemaDigest:
        "sha256:8d9bf7580e0ad223f32b0970dfb52bf04cfc2145b076d58773ac4d0161706334",
      requestMaxEncodedBytes: 9 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 9 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "session.read": Object.freeze({
      schemaDigest:
        "sha256:565b20d4f8e57450e22353bf4f3c7d442a52556550d75677498d830dbd24982f",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 4 * MEBIBYTE,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "session.read-events": Object.freeze({
      schemaDigest:
        "sha256:5977ceb4b6124cef9972e0a063225b913edffed354720be0f0ee045cb45b7578",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "workspace.initialize": Object.freeze({
      schemaDigest:
        "sha256:0a2068979fdd7bb5c7760327e59b28a5fac43f4ed67b7193e5e2e1f15d5f9ab2",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "workspace.execute": Object.freeze({
      schemaDigest:
        "sha256:1685d7db9f62bcea53a70a6a04d6e9be89d15e541647b2da2e795216532f2025",
      requestMaxEncodedBytes: 9 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 9 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "workspace.lookup-invocation": Object.freeze({
      schemaDigest:
        "sha256:f13795a7e1d93342e32a39ad4418d6ebab46d5a9b63ab64b9fdfc7c5128fe832",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 9 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "user.initialize": Object.freeze({
      schemaDigest:
        "sha256:5b5f5229fe3eaf15f5d3e232e5c0163dde4b7bb79e9bc93a91678f678928f6be",
      requestMaxEncodedBytes: 3 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "user.execute": Object.freeze({
      schemaDigest:
        "sha256:ce635f6ea291fdbcbb6fffd6d2cd0466906a90ece82419aec464d77fff2b40e7",
      requestMaxEncodedBytes: 3 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "user.read": Object.freeze({
      schemaDigest:
        "sha256:4fa672962285b34d659dccd797d545686a2366b103653101503dab0c477d35d8",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 2 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "extension-state.initialize": Object.freeze({
      schemaDigest:
        "sha256:34d48d02c3f14da4bd8afbf885b3231c9e218422aa28a65bfdd97bbc45639f3b",
      requestMaxEncodedBytes: 3 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "extension-state.execute": Object.freeze({
      schemaDigest:
        "sha256:1ffb89a3e44c6f4451165fac947069db052c845a844689a0077e0484ddfed36b",
      requestMaxEncodedBytes: 3 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "extension-state.read": Object.freeze({
      schemaDigest:
        "sha256:4cea1d427ba4b0505926aa3c3f633cdf5886e52a0e88673b366b5b983b5dde92",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 2 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "capability-generation.initialize": Object.freeze({
      schemaDigest:
        "sha256:037679f0550c0c8f116c6847a60dae6da48f05ade682768fe791029da2db7612",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "capability-generation.execute": Object.freeze({
      schemaDigest:
        "sha256:b0a4fbbd060ac9d1b03a16d5f3b752eebfb0352c6d9b9bf6d0c6a5f59aa2e399",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "capability-generation.assert-current": Object.freeze({
      schemaDigest:
        "sha256:b7357ca7a85c4fc6b58fd1062a15a5ed454814880134360e54127855ddc65f1e",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "audit.initialize": Object.freeze({
      schemaDigest:
        "sha256:7d5e7682fd10a0bebe5051e0022946686798bceb0bc095eee5972bf821984c4f",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "audit.execute": Object.freeze({
      schemaDigest:
        "sha256:7bd26a94831524f136459f8d55660a77173d8356d7142529adafec3bf4828452",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "audit.read": Object.freeze({
      schemaDigest:
        "sha256:35cea7a44645299a4b02cc18bba2af942d0b5f94183ba463ec592ad64cc4744b",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 4 * MEBIBYTE,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
  });

export const HOST_RPC_CONTRACTS: Readonly<Record<HostRpcOperation, HostRpcContract>> =
  Object.freeze(
    Object.fromEntries(
      HOST_RPC_OPERATIONS.map((operation) => [
        operation,
        Object.freeze({
          ...HOST_RPC_SIZE_CONTRACTS[operation],
          requestMaxItems: STANDARD_MAX_ITEMS,
          responseMaxItems: STANDARD_MAX_ITEMS,
        }),
      ]),
    ) as unknown as Record<HostRpcOperation, HostRpcContract>,
  );

type KnownRpcErrorCode =
  | ControlAggregateErrorCode
  | HostContractErrorCode
  | SessionAggregateErrorCode
  | WorkspaceAggregateErrorCode
  | "INTERNAL_ERROR";

const SAFE_ERROR_MESSAGES = Object.freeze({
  INVALID_ARGUMENT: "The RPC request is invalid.",
  NOT_FOUND: "The requested resource was not found.",
  ALREADY_EXISTS: "The requested resource already exists.",
  CONFLICT: "The operation conflicts with current state.",
  IDEMPOTENCY_CONFLICT: "The idempotency key conflicts with an earlier request.",
  PERMISSION_DENIED: "The operation is not permitted.",
  FAILED_PRECONDITION: "A required precondition was not satisfied.",
  STALE_GENERATION: "The supplied generation is stale.",
  STALE_DISPATCH_ATTEMPT: "The supplied dispatch attempt is stale.",
  DIGEST_MISMATCH: "A supplied digest does not match its value.",
  NEEDS_CONFIRMATION: "The operation requires confirmation.",
  ABORTED: "The operation was aborted.",
  LEASE_EXPIRED: "The supplied lease has expired.",
  RESOURCE_EXHAUSTED: "The RPC response exceeds its operation limit.",
  STORAGE_CONTRACT: "The durable storage contract is unavailable.",
  CELL_ID_MISMATCH: "The request was routed to the wrong durable cell.",
  NOT_INITIALIZED: "The durable aggregate is not initialized.",
  INITIALIZATION_CONFLICT: "The initialization conflicts with stored state.",
  STRUCTURED_CLONE_FAILED: "The value cannot cross the durable storage boundary.",
  CORRUPT_STATE: "The durable aggregate state is invalid.",
  INVALID_AGGREGATE_OUTPUT: "The aggregate produced an invalid result.",
  INTERNAL_ERROR: "The operation could not be completed.",
} as const satisfies Record<KnownRpcErrorCode, string>);

export type HostRpcErrorCode = keyof typeof SAFE_ERROR_MESSAGES;

export interface HostRpcError {
  readonly code: HostRpcErrorCode;
  readonly message: (typeof SAFE_ERROR_MESSAGES)[HostRpcErrorCode];
}

export interface HostRpcFailure {
  readonly ok: false;
  readonly error: HostRpcError;
}

export type HostRpcWireResult<Result> = Result extends void ? null : Result;

export interface HostRpcSuccess<Result> {
  readonly ok: true;
  readonly result: HostRpcWireResult<Result>;
}

export type HostRpcResult<Result> = HostRpcSuccess<Result> | HostRpcFailure;
export type HostRpcResponse<Result> = RpcEnvelope<HostRpcResult<Result>>;

export const HOST_RPC_FALLBACK_REQUEST_ID = "invalid-request" as const;

function responseEnvelope<Result>(
  contract: HostRpcContract,
  requestId: string,
  payload: HostRpcResult<Result>,
): RpcEnvelope<HostRpcResult<Result>> {
  return parseRpcEnvelope(
    {
      protocol: PROTOCOL_NAME,
      major: PROTOCOL_MAJOR,
      minor: PROTOCOL_MINOR,
      schemaDigest: contract.schemaDigest,
      requestId,
      payload,
    },
    (value) => normalizeProtocolValue(value, {
      maxDepth: contract.responseMaxDepth,
      maxItems: contract.responseMaxItems,
    }),
    {
      expectedSchemaDigest: contract.schemaDigest,
      maxEncodedBytes: contract.responseMaxEncodedBytes,
      maxDepth: contract.responseMaxDepth,
      maxItems: contract.responseMaxItems,
    },
  ) as unknown as RpcEnvelope<HostRpcResult<Result>>;
}

function failurePayload(code: HostRpcErrorCode): HostRpcFailure {
  return {
    ok: false,
    error: { code, message: SAFE_ERROR_MESSAGES[code] },
  };
}

function sanitizedFailure(error: unknown): HostRpcFailure {
  if (error instanceof ProtocolValidationError) {
    return failurePayload("INVALID_ARGUMENT");
  }
  if ((typeof error !== "object" && typeof error !== "function") || error === null) {
    return failurePayload("INTERNAL_ERROR");
  }

  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = Object.getOwnPropertyDescriptor(error, "code");
  } catch {
    return failurePayload("INTERNAL_ERROR");
  }
  if (descriptor === undefined || !("value" in descriptor)) {
    return failurePayload("INTERNAL_ERROR");
  }
  const code = descriptor.value;
  if (
    typeof code !== "string" ||
    !Object.prototype.hasOwnProperty.call(SAFE_ERROR_MESSAGES, code)
  ) {
    return failurePayload("INTERNAL_ERROR");
  }
  return failurePayload(code as HostRpcErrorCode);
}

export async function invokeHostRpc<Request, Result>(
  operation: HostRpcOperation,
  unknownEnvelope: unknown,
  payloadParser: ValueParser<Request>,
  action: (payload: Request) => Result | Promise<Result>,
): Promise<RpcEnvelope<HostRpcResult<Result>>> {
  const contract = HOST_RPC_CONTRACTS[operation];
  let request: RpcEnvelope<Request>;
  try {
    const preflight = parseRpcEnvelope(
      unknownEnvelope,
      (payload) => normalizeProtocolValue(payload, {
        maxDepth: contract.requestMaxDepth,
        maxItems: contract.requestMaxItems,
      }),
      {
        expectedSchemaDigest: contract.schemaDigest,
        maxEncodedBytes: contract.requestMaxEncodedBytes,
        maxDepth: contract.requestMaxDepth,
        maxItems: contract.requestMaxItems,
      },
    );
    request = parseRpcEnvelope(
      preflight,
      (payload) => normalizeProtocolValue(payloadParser(payload), {
        maxDepth: contract.requestMaxDepth,
        maxItems: contract.requestMaxItems,
      }) as Request,
      {
        expectedSchemaDigest: contract.schemaDigest,
        maxEncodedBytes: contract.requestMaxEncodedBytes,
        maxDepth: contract.requestMaxDepth,
        maxItems: contract.requestMaxItems,
      },
    );
  } catch {
    return responseEnvelope(
      contract,
      HOST_RPC_FALLBACK_REQUEST_ID,
      failurePayload("INVALID_ARGUMENT"),
    );
  }

  let result: Result;
  try {
    result = await action(request.payload);
  } catch (error) {
    return responseEnvelope(contract, request.requestId, sanitizedFailure(error));
  }

  try {
    return responseEnvelope(contract, request.requestId, {
      ok: true,
      result: (result === undefined ? null : result) as HostRpcWireResult<Result>,
    });
  } catch {
    return responseEnvelope(
      contract,
      request.requestId,
      failurePayload("RESOURCE_EXHAUSTED"),
    );
  }
}
