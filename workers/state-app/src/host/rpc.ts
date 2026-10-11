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
        "sha256:08a932591b57f378afc0187d9a3cffdbba0b9b3709583681613073e11bae0908",
      requestMaxEncodedBytes: 2 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "session.execute": Object.freeze({
      schemaDigest:
        "sha256:f83528ea0db0f1608046c9a44b770b06a89eaea348a1379106a39271d5381c90",
      requestMaxEncodedBytes: 9 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 9 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "session.read": Object.freeze({
      schemaDigest:
        "sha256:2dbea60b23caacd8516f2b116f5f4518a283886d8e96298d2c1308ca2bad295c",
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
        "sha256:b06366cdf19b231e67ad5913d7c0259001de0eee343964d1b49b11c3ddc8219d",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 4 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "session.read-events": Object.freeze({
      schemaDigest:
        "sha256:4aa0f7c0399fe8aec4dd7dad61763c12c08eb6a7283a727d83ede867050d0466",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "workspace.initialize": Object.freeze({
      schemaDigest:
        "sha256:54817fc2004e254b4508da091a572c2ace92f95d2aeffbe8d1bf37904f12fc61",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "workspace.execute": Object.freeze({
      schemaDigest:
        "sha256:52edd4d1749afca1aa911e7eb7b057e34b15c45670d2226638c4147645dc3d43",
      requestMaxEncodedBytes: 9 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 9 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "workspace.lookup-invocation": Object.freeze({
      schemaDigest:
        "sha256:0417a8112bf934c8fcb3c3f144ca1f46b183e20c8423f4e196d2e664d8d7aa77",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 9 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "user.initialize": Object.freeze({
      schemaDigest:
        "sha256:823e93ed0ca576ae903255559bd5a07811287c0cc48956684e785d559d963512",
      requestMaxEncodedBytes: 3 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "user.execute": Object.freeze({
      schemaDigest:
        "sha256:305aa45309c66ee55265585a1511dae427b8587b1881e95d9f4c5097cc92eeee",
      requestMaxEncodedBytes: 3 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "user.read": Object.freeze({
      schemaDigest:
        "sha256:9d7a8932bf476a245479a9bba5672be21c83daac0d798f03650c02fcb3b240b0",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 2 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "extension-state.initialize": Object.freeze({
      schemaDigest:
        "sha256:70bd9c4bb13ad241453a303a956cc4b133195db2adc63f37bac66db134f67723",
      requestMaxEncodedBytes: 3 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "extension-state.execute": Object.freeze({
      schemaDigest:
        "sha256:a358b040e73456c104f46daa8a2f5ad8811202915dadff08ee30226e876308c7",
      requestMaxEncodedBytes: 3 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "extension-state.read": Object.freeze({
      schemaDigest:
        "sha256:e0d1417628aa378060f48eb911e7f3ab2c6117b7724119511641c7d116d44958",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 2 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "capability-generation.initialize": Object.freeze({
      schemaDigest:
        "sha256:b9cd8b89a3ecedccbf55e163d3c15502af1af32b500b7a8e36266980ee991d89",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "capability-generation.execute": Object.freeze({
      schemaDigest:
        "sha256:fea75874413bb4cdf04f95beecce9dc4c0328f233dfd7c5cfc0aec99c3fe97e7",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "capability-generation.assert-current": Object.freeze({
      schemaDigest:
        "sha256:81b5e709bf3e488d0757637508849e3c11934031efe7f9c98771349f7cc722cb",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "audit.initialize": Object.freeze({
      schemaDigest:
        "sha256:214b16a647ccba67eb2ec1e82eddc06d37f7f0bb282a6608467dbc90cc69071e",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "audit.execute": Object.freeze({
      schemaDigest:
        "sha256:0c188d1ffcc3a7d8997d0a64ad22bee7a9259b3dcfa63e95aeabba402990d485",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "audit.read": Object.freeze({
      schemaDigest:
        "sha256:c16f88e04516c05e41847c092c4a039bff31ea04909bc5d093cc211be0355cb0",
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
