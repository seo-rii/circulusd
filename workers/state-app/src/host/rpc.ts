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
        "sha256:3ee255a3d28dae86a5bc984bc8080f1b38a57826f4b67740eec8fb825770128b",
      requestMaxEncodedBytes: 2 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "session.execute": Object.freeze({
      schemaDigest:
        "sha256:6823545b5f7299f5303e9d9e9cc9f8b638a61d8003dcc5156421febcad4a2528",
      requestMaxEncodedBytes: 9 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 9 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "session.read": Object.freeze({
      schemaDigest:
        "sha256:aa7904d06f40a3629441219cfc16fd0d5bc0f5f50511e88e6f739aaf5f668c91",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 4 * MEBIBYTE,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "session.read-events": Object.freeze({
      schemaDigest:
        "sha256:11301a937f70c946b90918669089a4cac298a273c222940d0fe4801a7d52b2ba",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "workspace.initialize": Object.freeze({
      schemaDigest:
        "sha256:7e1e40550871780835363e98ed781a99238e014b4ed676d71afd5a6776d21244",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "workspace.execute": Object.freeze({
      schemaDigest:
        "sha256:6ed3fd228872aebdae93ca3b9b6e55de3081c8f2a163661c52b975c59ae46485",
      requestMaxEncodedBytes: 9 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 9 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "workspace.lookup-invocation": Object.freeze({
      schemaDigest:
        "sha256:7d6463ba3559400f716bb3935eaaedc4ebbe1cdd9ac4ad967e82a44effcefe25",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 9 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "user.initialize": Object.freeze({
      schemaDigest:
        "sha256:516a1d7b448438c29424003daecae8226b17519e223c04bf019516b598deeff2",
      requestMaxEncodedBytes: 3 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "user.execute": Object.freeze({
      schemaDigest:
        "sha256:4da1dc3928344268f9b6b1371265aba7123d285b15be0279359619e69c069231",
      requestMaxEncodedBytes: 3 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "user.read": Object.freeze({
      schemaDigest:
        "sha256:b4664353f8ac1f98d590f52548952d90654c900778c133e264da555bf7919d8d",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 2 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "extension-state.initialize": Object.freeze({
      schemaDigest:
        "sha256:9c00ea2c454bcea962e1a6e264fac55945e47499369e1be772e068ae05bd39d6",
      requestMaxEncodedBytes: 3 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "extension-state.execute": Object.freeze({
      schemaDigest:
        "sha256:b46c54f6e2d2ffb6369edd3fe374231847e35fbbb043f76e8cfc3d5fe2f45044",
      requestMaxEncodedBytes: 3 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "extension-state.read": Object.freeze({
      schemaDigest:
        "sha256:13e07665ab2ad3e71cc4a135940551ac3dfb6a110227a11d55f0a922216f94e7",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: 2 * MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "capability-generation.initialize": Object.freeze({
      schemaDigest:
        "sha256:1f724eb596301eeda6bd78fb998c28cfca496e12176009eea501374260409ac9",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "capability-generation.execute": Object.freeze({
      schemaDigest:
        "sha256:65927b95d07777b37f9685fe9e111207ff19d27f68781bae0b49c41edecec712",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "capability-generation.assert-current": Object.freeze({
      schemaDigest:
        "sha256:1b3d23a63c604f0a726f7eb58d9515ab5a2d407eac292b9e713cd395d80f9a02",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "audit.initialize": Object.freeze({
      schemaDigest:
        "sha256:b77c231650e9aa3d2d9c99a28ba21335ee181316e265f98b12753c2a7fdbc474",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "audit.execute": Object.freeze({
      schemaDigest:
        "sha256:1d10a5cc24770da55e4372e38ee401acbeac68a7c2aea0246407128892c2cb05",
      requestMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      requestMaxDepth: STANDARD_MAX_DEPTH,
      responseMaxEncodedBytes: MEBIBYTE + ENVELOPE_HEADROOM_BYTES,
      responseMaxDepth: STANDARD_MAX_DEPTH,
    }),
    "audit.read": Object.freeze({
      schemaDigest:
        "sha256:a4204d1d11483e8ece179840834c9fe0fff2f87a339c77beb120426eeaa16895",
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
