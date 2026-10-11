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
  "session.read-blob",
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
        "sha256:5a0b28de7fefe0e49f7f6909e60ccb3dde33b5c8ad4db49df9657509cdd19142",
      requestMaxEncodedBytes: 2 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "session.execute": Object.freeze({
      schemaDigest:
        "sha256:0cfbf95ebc837225746cf03c0bef6f018a4452815e90d775bc4d6cd516a99656",
      requestMaxEncodedBytes: 9 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 9 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "session.read": Object.freeze({
      schemaDigest:
        "sha256:59ecd31cb67d77f2a54917fbda8453b86db517abfba484fca55e6891026b40c6",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 4 * MEBIBYTE,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    // One externalized payload blob (storage redesign stage B): a checkpoint's
    // bytes may reach MAX_BLOB_BYTES (4 MiB), framed by the result object and the
    // envelope.
    "session.read-blob": Object.freeze({
      schemaDigest:
        "sha256:f35122bf697af5d0d53f34b8f0a20b1c2d1be7dc00b35bcf03e95a5ab25f9209",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 4 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "session.read-events": Object.freeze({
      schemaDigest:
        "sha256:da3da23fa27c8b45de68448dc572299e2472b6a2f10508b4336761ce57a086ab",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "workspace.initialize": Object.freeze({
      schemaDigest:
        "sha256:d7ef22ff43b37ff8150fa6138ef113c9e5d5123040233f2a8b2ca6cca74c7301",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "workspace.execute": Object.freeze({
      schemaDigest:
        "sha256:89d0e251a92b55242b75c8b45cef215afd261b5bac981bcd9d332e65b15b7bb4",
      requestMaxEncodedBytes: 9 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 9 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "workspace.lookup-invocation": Object.freeze({
      schemaDigest:
        "sha256:f1268c61bcd1624f461b832714667a931336cef4e73dbdee8f39273efeddfb5d",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 9 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "user.initialize": Object.freeze({
      schemaDigest:
        "sha256:b26cef99b675b8889cc0a88c16779ed2b4c632b1092efdbe11fc6327d3aeb644",
      requestMaxEncodedBytes: 3 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "user.execute": Object.freeze({
      schemaDigest:
        "sha256:a3bb3106eecf9304cffe4c7500edc7334128b43cd1cb050ed55ca0800432d93d",
      requestMaxEncodedBytes: 3 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "user.read": Object.freeze({
      schemaDigest:
        "sha256:3eb6a796e2567dbd32d074c9a40bb032bee69aff701520defedc9aede7fa6bd1",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 2 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "extension-state.initialize": Object.freeze({
      schemaDigest:
        "sha256:e6494189db2fb6603569a3db306622a014f407f648b6449604e0aa701a1f31c8",
      requestMaxEncodedBytes: 3 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "extension-state.execute": Object.freeze({
      schemaDigest:
        "sha256:030f3b464bf29d55bb59ec8dd2d904704ca5f9225c8b4b4efe4b89e5d53c765b",
      requestMaxEncodedBytes: 3 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "extension-state.read": Object.freeze({
      schemaDigest:
        "sha256:5efab07d67db445d57b5935b770199e4c8f953a5e4fd10d46075ee61f586aafe",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 2 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "capability-generation.initialize": Object.freeze({
      schemaDigest:
        "sha256:4ae137539e26d04e13b6c216e5351af8cfb4e9e4f5076ffe248f580d2c5155a5",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "capability-generation.execute": Object.freeze({
      schemaDigest:
        "sha256:cac82ff983468bc42b17e0147d33768db37cbdb3d1f1d3eccb529b9933a171a5",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "capability-generation.assert-current": Object.freeze({
      schemaDigest:
        "sha256:735d65c15fb6e3b45e55649042d4142b3c998fd25804388b732ffead97eb82c4",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "audit.initialize": Object.freeze({
      schemaDigest:
        "sha256:40ee9be774c1071c52acabc4c50ae9a5b55ff791231ccec71b97e962092e2976",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "audit.execute": Object.freeze({
      schemaDigest:
        "sha256:c8bab2fac9991bdf8de4c4924c74d5c78004271359e8358dade86d1d8091f55b",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "audit.read": Object.freeze({
      schemaDigest:
        "sha256:8af03551bbf92e3d4611488b50d7f12393768df274a2aa129308d30b279b9b89",
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
  DISPATCH_ALREADY_STARTED: "The dispatch attempt already has a start claim.",
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
