import { describe, expect, it } from "vitest";

import {
  PROTOCOL_MAJOR,
  PROTOCOL_MINOR,
  PROTOCOL_NAME,
  encodeCanonicalCbor,
  parseNormalizedValue,
  parseRpcEnvelope,
  type NormalizedValue,
} from "@circulusd/protocol-types";

import {
  HOST_RPC_CONTRACTS,
  HOST_RPC_FALLBACK_REQUEST_ID,
  HOST_RPC_OPERATIONS,
  invokeHostRpc,
  type HostRpcOperation,
} from "../src/host/rpc.ts";
import {
  SCHEMA_SOURCE_FILES,
  computeHostRpcSchemaDigest,
} from "../scripts/generate-rpc-digests.mjs";

const MEBIBYTE = 1_048_576;

const GOLDEN_SCHEMA_DIGESTS = {
  "session.initialize":
    "sha256:4e6350211b42d90f5054e197a579085ca67f1f2adae387c9cb0759015d57a2d3",
  "session.execute":
    "sha256:563af9946d02a2c5c8301654e77d07c2837a295b38badefc2a1e0e0ada9a8f88",
  "session.read":
    "sha256:efbc07b68890f075fd511ba3f6860f40020fdc79627ab887c2c087efe3d80c36",
  "session.read-events":
    "sha256:cbf7a511819dd9c23293844bdb24db5eb9776613080ea34844002ddaa82101c3",
  "workspace.initialize":
    "sha256:2f262419ff61dbc8c72273b046b531485107573f6f1601e5e7f0835beb3bf7b2",
  "workspace.execute":
    "sha256:75a30888a86fc5bdeeded59daed325b4175f4d4ca113af21468e5fcc79c708ce",
  "workspace.lookup-invocation":
    "sha256:7823fe6ee7b53dd1910010693c972d2685b12ccf14cbc1a913a3a0668e0c23c7",
  "user.initialize":
    "sha256:81937db33e4070a92895cd86f831b3c04a991a3b9ba120cab6d3a91a921167be",
  "user.execute":
    "sha256:0e15e046dd09b30dca21578a6a8b039fadb96e36aa9df040956832e58cc62cf6",
  "user.read":
    "sha256:83e6823721c00aa3007824a7ce369289858cacf5ba9fcf97b03c8a11a71fddd7",
  "extension-state.initialize":
    "sha256:abd57e6d643e891aecb0048fde155c7d330c56f9cb2c4efecbea1e280edb30f4",
  "extension-state.execute":
    "sha256:db24002efd4ee153ccd5b85776225ce8843f154df7726040f45ee86d34500b20",
  "extension-state.read":
    "sha256:f7fe2bcf862fa7c88e4c9dd5c97283c7c20b0615ef3511eb0d108a20edade724",
  "capability-generation.initialize":
    "sha256:bec7a02008042f5069ec11f2c13b4e36603d7058e5033c822d01f680870a52ce",
  "capability-generation.execute":
    "sha256:ad33da1a0be57df72995eb51839194314feac75311ee167984b57f9ec84d84b6",
  "capability-generation.assert-current":
    "sha256:1835ada25359df10c8f2ad85efcd688da7272bebf85a4782c01ba4a999a914ce",
  "audit.initialize":
    "sha256:4f6cfcefe075e9daf12030db98eb2481cc608aa5a9d9b5c9f1aef433aa50d81f",
  "audit.execute":
    "sha256:b1e996b5a4a3ca87162f54c6681c5ae2078e79855a9c779dde4cdd1f67c2a936",
  "audit.read":
    "sha256:74a0e6f566133559ee81ee6ead0cb5adbbd7b998c74025fdcb3e89b6f3af4a31",
} as const satisfies Record<HostRpcOperation, `sha256:${string}`>;

function requestEnvelope(
  operation: HostRpcOperation,
  payload: unknown,
  requestId = "request-01",
): Record<string, unknown> {
  return {
    protocol: PROTOCOL_NAME,
    major: PROTOCOL_MAJOR,
    minor: PROTOCOL_MINOR,
    schemaDigest: HOST_RPC_CONTRACTS[operation].schemaDigest,
    requestId,
    payload,
  };
}

function validatedResponsePayload(
  operation: HostRpcOperation,
  value: unknown,
): Record<string, NormalizedValue> {
  const contract = HOST_RPC_CONTRACTS[operation];
  const envelope = parseRpcEnvelope(value, parseNormalizedValue, {
    expectedSchemaDigest: contract.schemaDigest,
    maxEncodedBytes: contract.responseMaxEncodedBytes,
    maxDepth: contract.responseMaxDepth,
  });
  expect(envelope.protocol).toBe(PROTOCOL_NAME);
  expect(envelope.major).toBe(PROTOCOL_MAJOR);
  expect(envelope.minor).toBe(PROTOCOL_MINOR);
  return envelope.payload as Record<string, NormalizedValue>;
}

describe("state host RPC contracts", () => {
  it("derives every wire identity from the implemented request, response, and error schemas", () => {
    expect(SCHEMA_SOURCE_FILES).toContain(
      "../../../packages/protocol-types/src/digest.ts",
    );
    expect(SCHEMA_SOURCE_FILES).toContain("../src/host/audit-kernel.ts");
    expect(SCHEMA_SOURCE_FILES).toContain("../src/host/kernel.ts");
    for (const operation of HOST_RPC_OPERATIONS) {
      expect(HOST_RPC_CONTRACTS[operation].schemaDigest).toBe(
        computeHostRpcSchemaDigest(operation),
      );
    }
  });

  it("pins 19 separated operation schemas and explicit request/response limits", () => {
    expect(HOST_RPC_OPERATIONS).toHaveLength(19);
    expect(HOST_RPC_CONTRACTS).toEqual(
      expect.objectContaining(
        Object.fromEntries(
          Object.entries(GOLDEN_SCHEMA_DIGESTS).map(([operation, schemaDigest]) => [
            operation,
            expect.objectContaining({ schemaDigest }),
          ]),
        ),
      ),
    );
    expect(new Set(HOST_RPC_OPERATIONS)).toEqual(
      new Set(Object.keys(GOLDEN_SCHEMA_DIGESTS)),
    );
    expect(
      new Set(HOST_RPC_OPERATIONS.map((operation) =>
        HOST_RPC_CONTRACTS[operation].schemaDigest)),
    ).toHaveLength(19);

    for (const operation of HOST_RPC_OPERATIONS) {
      const contract = HOST_RPC_CONTRACTS[operation];
      expect(Object.keys(contract).sort()).toEqual([
        "requestMaxDepth",
        "requestMaxEncodedBytes",
        "requestMaxItems",
        "responseMaxDepth",
        "responseMaxEncodedBytes",
        "responseMaxItems",
        "schemaDigest",
      ]);
      expect(contract.requestMaxEncodedBytes).toBeGreaterThan(512);
      expect(contract.responseMaxEncodedBytes).toBeGreaterThan(512);
      expect(contract.requestMaxDepth).toBeGreaterThan(2);
      expect(contract.responseMaxDepth).toBeGreaterThan(2);
      expect(contract.requestMaxItems).toBeGreaterThan(100);
      expect(contract.requestMaxItems).toBeLessThanOrEqual(100_000);
      expect(contract.responseMaxItems).toBeGreaterThan(100);
      expect(contract.responseMaxItems).toBeLessThanOrEqual(100_000);
    }

    expect(
      HOST_RPC_CONTRACTS["session.execute"].requestMaxEncodedBytes,
    ).toBeGreaterThanOrEqual(9 * MEBIBYTE);
    expect(HOST_RPC_CONTRACTS["session.read"].responseMaxEncodedBytes).toBeGreaterThan(
      3 * MEBIBYTE,
    );
    expect(
      HOST_RPC_CONTRACTS["session.read-events"].responseMaxEncodedBytes,
    ).toBeLessThanOrEqual(2 * MEBIBYTE);
    expect(HOST_RPC_CONTRACTS["user.read"].responseMaxEncodedBytes).toBeGreaterThan(
      2 * MEBIBYTE,
    );
    expect(
      HOST_RPC_CONTRACTS["extension-state.read"].responseMaxEncodedBytes,
    ).toBeGreaterThan(2 * MEBIBYTE);
    expect(HOST_RPC_CONTRACTS["audit.read"].responseMaxEncodedBytes).toBeLessThanOrEqual(
      4 * MEBIBYTE,
    );
  });

  it("keeps a maximum public-event page within the read-events response limit", () => {
    const maximumIdentifier = "x".repeat(256);
    const events = Array.from({ length: 256 }, (_, index) => ({
      sequence: index + 1,
      type: "tool.externally_committed",
      turnId: maximumIdentifier,
      turnSequence: index,
      effectId: maximumIdentifier,
      invocationId: maximumIdentifier,
      service: "external-tool",
      operation: maximumIdentifier,
      externalCommitId: maximumIdentifier,
      resultRef: maximumIdentifier,
    }));
    const encoded = encodeCanonicalCbor({
      protocol: PROTOCOL_NAME,
      major: PROTOCOL_MAJOR,
      minor: PROTOCOL_MINOR,
      schemaDigest: HOST_RPC_CONTRACTS["session.read-events"].schemaDigest,
      requestId: maximumIdentifier,
      payload: {
        ok: true,
        result: {
          snapshot: {
            sessionId: maximumIdentifier,
            activeTurnId: maximumIdentifier,
            turnStatus: "needs_confirmation",
            lastEventSequence: 256,
          },
          events,
        },
      },
    });
    expect(encoded.byteLength).toBeLessThan(
      HOST_RPC_CONTRACTS["session.read-events"].responseMaxEncodedBytes,
    );
  });

  it("normalizes and detaches a valid request and returns a validated response", async () => {
    const sourceBytes = new Uint8Array([1, 2, 3]);
    const sourcePayload = { label: "A\u030A", bytes: sourceBytes };
    let actionPayload: { label: string; bytes: Uint8Array } | undefined;
    const sourceResult = { accepted: true, receipt: new Uint8Array([8, 9]) };

    const response = await invokeHostRpc(
      "session.initialize",
      requestEnvelope("session.initialize", sourcePayload),
      (value) => value as { label: string; bytes: Uint8Array },
      (payload) => {
        actionPayload = payload;
        return sourceResult;
      },
    );

    expect(actionPayload).toEqual({ label: "Å", bytes: new Uint8Array([1, 2, 3]) });
    expect(actionPayload).not.toBe(sourcePayload);
    expect(actionPayload?.bytes).not.toBe(sourceBytes);
    expect(response.requestId).toBe("request-01");
    expect(response.schemaDigest).toBe(GOLDEN_SCHEMA_DIGESTS["session.initialize"]);
    expect(response.payload).toEqual({ ok: true, result: sourceResult });
    expect(response.payload).not.toBe(sourceResult);
    expect(response.payload.result).not.toBe(sourceResult);
    expect(validatedResponsePayload("session.initialize", response)).toEqual({
      ok: true,
      result: sourceResult,
    });
  });

  it("maps a void action result to canonical null", async () => {
    const response = await invokeHostRpc(
      "capability-generation.assert-current",
      requestEnvelope("capability-generation.assert-current", { generation: 7 }),
      parseNormalizedValue,
      () => undefined,
    );

    expect(response.payload).toEqual({ ok: true, result: null });
  });

  it("preserves aggregate values at the canonical 64-level depth inside response framing", async () => {
    const aggregateValue: Record<string, unknown> = {};
    let cursor = aggregateValue;
    for (let depth = 0; depth < 64; depth += 1) {
      const next: Record<string, unknown> = {};
      cursor.next = next;
      cursor = next;
    }

    const response = await invokeHostRpc(
      "user.read",
      requestEnvelope("user.read", null, "request-deep-state"),
      parseNormalizedValue,
      () => aggregateValue,
    );

    expect(response.requestId).toBe("request-deep-state");
    expect(response.payload).toMatchObject({ ok: true });
  });

  it("rejects malformed envelopes before invoking the action", async () => {
    const operation = "user.execute" as const;
    const valid = requestEnvelope(operation, { command: "replace" });
    const malformed: unknown[] = [
      { command: "replace" },
      { ...valid, protocol: "circulus.v1" },
      { ...valid, major: PROTOCOL_MAJOR + 1 },
      { ...valid, minor: PROTOCOL_MINOR + 1 },
      { ...valid, schemaDigest: GOLDEN_SCHEMA_DIGESTS["audit.execute"] },
      { ...valid, requestId: "" },
      { ...valid, requestId: "request\u0000secret" },
      { ...valid, alias: valid.payload },
    ];
    let actionCalls = 0;

    for (const candidate of malformed) {
      const response = await invokeHostRpc(
        operation,
        candidate,
        parseNormalizedValue,
        () => {
          actionCalls += 1;
          return { unreachable: true };
        },
      );
      expect(response.requestId).toBe(HOST_RPC_FALLBACK_REQUEST_ID);
      expect(response.schemaDigest).toBe(GOLDEN_SCHEMA_DIGESTS[operation]);
      expect(response.payload).toEqual({
        ok: false,
        error: {
          code: "INVALID_ARGUMENT",
          message: "The RPC request is invalid.",
        },
      });
      validatedResponsePayload(operation, response);
    }
    expect(actionCalls).toBe(0);
  });

  it("does not let one operation schema authorize another operation", async () => {
    let actionCalls = 0;
    const response = await invokeHostRpc(
      "audit.read",
      requestEnvelope("user.read", { authority: {}, now: 1 }),
      parseNormalizedValue,
      () => {
        actionCalls += 1;
        return [];
      },
    );

    expect(actionCalls).toBe(0);
    expect(response.schemaDigest).toBe(GOLDEN_SCHEMA_DIGESTS["audit.read"]);
    expect(response.requestId).toBe(HOST_RPC_FALLBACK_REQUEST_ID);
  });

  it("preflights raw encoded size, depth, aliases, and accessors before parsing or action", async () => {
    const operation = "session.initialize" as const;
    const contract = HOST_RPC_CONTRACTS[operation];
    let parserCalls = 0;
    let actionCalls = 0;
    const invoke = (input: unknown) => invokeHostRpc(
      operation,
      input,
      (value) => {
        parserCalls += 1;
        return value;
      },
      () => {
        actionCalls += 1;
        return { unreachable: true };
      },
    );

    const oversized = requestEnvelope(
      operation,
      "x".repeat(contract.requestMaxEncodedBytes),
    );
    const nested: Record<string, unknown> = {};
    let cursor = nested;
    for (let depth = 0; depth < contract.requestMaxDepth + 2; depth += 1) {
      const next: Record<string, unknown> = {};
      cursor.next = next;
      cursor = next;
    }
    const shared = { value: 1 };

    let getterReads = 0;
    const accessorEnvelope = requestEnvelope(operation, null);
    Object.defineProperty(accessorEnvelope, "payload", {
      enumerable: true,
      get() {
        getterReads += 1;
        return null;
      },
    });

    for (const input of [
      oversized,
      requestEnvelope(operation, nested),
      requestEnvelope(operation, { first: shared, second: shared }),
      accessorEnvelope,
    ]) {
      const response = await invoke(input);
      expect(response.payload).toMatchObject({
        ok: false,
        error: { code: "INVALID_ARGUMENT" },
      });
    }
    expect(parserCalls).toBe(0);
    expect(actionCalls).toBe(0);
    expect(getterReads).toBe(0);
  });

  it("treats semantic parser rejection as an invalid request before action", async () => {
    let actionCalls = 0;
    const response = await invokeHostRpc(
      "workspace.execute",
      requestEnvelope("workspace.execute", { kind: "unknown" }),
      () => {
        throw new Error("parser detail must not escape");
      },
      () => {
        actionCalls += 1;
        return null;
      },
    );

    expect(actionCalls).toBe(0);
    expect(response.requestId).toBe(HOST_RPC_FALLBACK_REQUEST_ID);
    expect(response.payload).toEqual({
      ok: false,
      error: { code: "INVALID_ARGUMENT", message: "The RPC request is invalid." },
    });
  });

  it("returns allowlisted domain failures without reading message, stack, or details", async () => {
    let sensitiveReads = 0;
    const failure = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(failure, "code", {
      enumerable: true,
      value: "CONFLICT",
    });
    for (const key of ["message", "stack", "details"]) {
      Object.defineProperty(failure, key, {
        enumerable: true,
        get() {
          sensitiveReads += 1;
          throw new Error("sensitive accessor was read");
        },
      });
    }

    const response = await invokeHostRpc(
      "workspace.execute",
      requestEnvelope("workspace.execute", { command: "commit" }, "request-domain"),
      parseNormalizedValue,
      () => {
        throw failure;
      },
    );

    expect(sensitiveReads).toBe(0);
    expect(response.requestId).toBe("request-domain");
    expect(response.payload).toEqual({
      ok: false,
      error: {
        code: "CONFLICT",
        message: "The operation conflicts with current state.",
      },
    });
    validatedResponsePayload("workspace.execute", response);
  });

  it("preserves every current host-boundary error code through the fixed allowlist", async () => {
    const response = await invokeHostRpc(
      "user.initialize",
      requestEnvelope("user.initialize", null, "request-cell-route"),
      parseNormalizedValue,
      () => {
        throw Object.assign(Object.create(null), { code: "CELL_ID_MISMATCH" });
      },
    );

    expect(response.payload).toEqual({
      ok: false,
      error: {
        code: "CELL_ID_MISMATCH",
        message: "The request was routed to the wrong durable cell.",
      },
    });
  });

  it("maps unknown and accessor-backed codes to a generic internal failure", async () => {
    for (const variant of ["unknown-data", "accessor"] as const) {
      let accessorReads = 0;
      const failure = Object.create(null) as Record<string, unknown>;
      Object.defineProperty(failure, "code", variant === "unknown-data"
        ? { enumerable: true, value: "DATABASE_PASSWORD_LEAK" }
        : {
            enumerable: true,
            get() {
              accessorReads += 1;
              return "CONFLICT";
            },
          });
      for (const key of ["message", "stack", "details"]) {
        Object.defineProperty(failure, key, {
          get() {
            accessorReads += 1;
            return "secret";
          },
        });
      }

      const response = await invokeHostRpc(
        "audit.execute",
        requestEnvelope("audit.execute", { event: 1 }, `request-${variant}`),
        parseNormalizedValue,
        () => {
          throw failure;
        },
      );

      expect(accessorReads).toBe(0);
      expect(response.requestId).toBe(`request-${variant}`);
      expect(response.payload).toEqual({
        ok: false,
        error: {
          code: "INTERNAL_ERROR",
          message: "The operation could not be completed.",
        },
      });
    }
  });

  it("converts oversized, over-deep, and noncanonical action results to bounded failures", async () => {
    const operation = "session.initialize" as const;
    const contract = HOST_RPC_CONTRACTS[operation];
    const tooDeep: Record<string, unknown> = {};
    let cursor = tooDeep;
    for (let depth = 0; depth < contract.responseMaxDepth + 2; depth += 1) {
      const next: Record<string, unknown> = {};
      cursor.next = next;
      cursor = next;
    }
    let getterReads = 0;
    const accessorResult: Record<string, unknown> = {};
    Object.defineProperty(accessorResult, "secret", {
      enumerable: true,
      get() {
        getterReads += 1;
        return "must-not-be-read";
      },
    });

    for (const result of [
      "x".repeat(contract.responseMaxEncodedBytes),
      tooDeep,
      accessorResult,
    ]) {
      const response = await invokeHostRpc(
        operation,
        requestEnvelope(operation, null, "request-result-limit"),
        parseNormalizedValue,
        () => result,
      );
      expect(response.requestId).toBe("request-result-limit");
      expect(response.payload).toEqual({
        ok: false,
        error: {
          code: "RESOURCE_EXHAUSTED",
          message: "The RPC response exceeds its operation limit.",
        },
      });
      validatedResponsePayload(operation, response);
    }
    expect(getterReads).toBe(0);
  });
});
