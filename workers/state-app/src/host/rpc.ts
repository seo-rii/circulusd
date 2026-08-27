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
        "sha256:24a44318ba2b81582e7b6bfc801ffeaff309dd6fa2a246c0d4b711c1428e915d",
      requestMaxEncodedBytes: 2 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "session.execute": Object.freeze({
      schemaDigest:
        "sha256:e67f49d70a80b5a6e9811aeb7ea770cb0d4e1ea8ed3ee40e30c826bbf259ec44",
      requestMaxEncodedBytes: 9 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 9 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "workspace.initialize": Object.freeze({
      schemaDigest:
        "sha256:0029e9e2f45fc877243cd87b5046e844f198498e99d7afadb3f0e11c53653dbe",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "workspace.execute": Object.freeze({
      schemaDigest:
        "sha256:5afc0ee8111e543a7e0a7917f00c292d98aea92500eeadc80b50872f74bcef8a",
      requestMaxEncodedBytes: 9 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 9 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "workspace.lookup-invocation": Object.freeze({
      schemaDigest:
        "sha256:d04b688f0d33a7ef593b20affb95e21f64ee18ebe007c467a126f06fe7cc9a12",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 9 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "user.initialize": Object.freeze({
      schemaDigest:
        "sha256:f85c36c09dc27506ec75b42ae71466146259b7e4b148c400f4980463472825f5",
      requestMaxEncodedBytes: 3 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "user.execute": Object.freeze({
      schemaDigest:
        "sha256:c6f3ae98ea7f09deca7ae2c9b4dfa9c39fc6847ea0d69a7483f1233aa51f72cf",
      requestMaxEncodedBytes: 3 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "user.read": Object.freeze({
      schemaDigest:
        "sha256:2f3663b5c4b6923ce42c25bdfedf25b995511d0108e6d66ada789b81921e8e34",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 2 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "extension-state.initialize": Object.freeze({
      schemaDigest:
        "sha256:52b0e1d2571e45a7ce2b4d7926a350e345b1d19cffca8704cf6759fa2beabcee",
      requestMaxEncodedBytes: 3 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "extension-state.execute": Object.freeze({
      schemaDigest:
        "sha256:919261b4ddc6216c4cd849bcda87bc06fd7352a61b33879fc1c09f0ca5340e80",
      requestMaxEncodedBytes: 3 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "extension-state.read": Object.freeze({
      schemaDigest:
        "sha256:41727b485bc71413db7302077a8055fa6abe43e2b1520202365d635d6703238d",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 2 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "capability-generation.initialize": Object.freeze({
      schemaDigest:
        "sha256:aa9b35c71123310cd19836c4e214f54c496fba6fb6ade4e766a1f2bc6195b080",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "capability-generation.execute": Object.freeze({
      schemaDigest:
        "sha256:f597bac0cacdf624d5ee19ad8dcf92ecaec17296025d5b80b3591c9e5535b9ab",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "capability-generation.assert-current": Object.freeze({
      schemaDigest:
        "sha256:4fb18cfecd296c46a90f0a416adc11c48f366c51b8cd8960a51cb80e620bf9ac",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "audit.initialize": Object.freeze({
      schemaDigest:
        "sha256:5f4bdbc963b92f46f499c1cc3831498a171db60d91001ebb00f017dbc3b95cba",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "audit.execute": Object.freeze({
      schemaDigest:
        "sha256:4c507ca665749929daba7336cafbb051c787771a05679a52929b6ac76204dc4c",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "audit.read": Object.freeze({
      schemaDigest:
        "sha256:0e56303c90347bb5f449ff551010eddb5fdf80e8759339ce8b1bfa71c8e1a346",
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
