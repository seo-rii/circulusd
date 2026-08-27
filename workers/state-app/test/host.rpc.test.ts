import { describe, expect, it } from "vitest";

import {
  PROTOCOL_MAJOR,
  PROTOCOL_MINOR,
  PROTOCOL_NAME,
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
    "sha256:a2fd77db7b504367728147f55b355f5a06e7b3b6e307d425ce2d6d25686eb278",
  "session.execute":
    "sha256:ad9ad65775d83fb71e02aab52d85a39e7f4136b60948e0db622d233c9d6bf43d",
  "session.read":
    "sha256:bb04fed746e9c50db4baec42f2a0903d9e3bf955f2a5770af549c45383a37e99",
  "workspace.initialize":
    "sha256:bb6d5f476ffabca1d8aa6450b65cc0eef7ed6adf3e221d0bbe30c0f4127bcba0",
  "workspace.execute":
    "sha256:2773aacece38c522e80d42d58862ae6d26cb672fc2772dbb46bc5f2ee63ab563",
  "workspace.lookup-invocation":
    "sha256:ef1645220af92c4f983b41a57dd24b8aa98d5ea2021f6295f1b71d6fc3c278f3",
  "user.initialize":
    "sha256:484ebdc370de058a8ae22cc6fedbe0978b8fa90b099797fdb3336b2e0ecf04fb",
  "user.execute":
    "sha256:9b3793672672de8f076fe9c5415d6befcc48bbecb9c06976f053221ba320f6ed",
  "user.read":
    "sha256:1419c18f5765374edaf27206c9908416affe3f1628c3872e24c5807e32cf6e4c",
  "extension-state.initialize":
    "sha256:ab3ede0be07cdd96f3f3d299adb79b168f9f7f0adc19b362829067fa32e79f6e",
  "extension-state.execute":
    "sha256:5d7e9cff751305fc4469641b15d6335030e2a08b5cf71112776021fc7447673e",
  "extension-state.read":
    "sha256:2bdb526ce79f83e9f2a8bbfdb7fa1cce4bb29d0f8c76d5f568ecc4847c564a3a",
  "capability-generation.initialize":
    "sha256:34775514d28693a14d50bd83f9baef1c26f852c532d7322ba2acd9cfe3cfef87",
  "capability-generation.execute":
    "sha256:30d1ca470b41611d50598ff40582186c96b7cf28a49b37ccfe777f4365501d2e",
  "capability-generation.assert-current":
    "sha256:ca055c45f41c8bb604b07ac0e2afa91e9c94f6ca8daff73b55131e3e5d2168c1",
  "audit.initialize":
    "sha256:77a1688ce217dd1843486e0cc8e8fda617176040b9affa24922345de8d9b7498",
  "audit.execute":
    "sha256:166e61b727b94117903fb3506d3c1806bcf28e5ccc8731b3d8dfdb2083a1d257",
  "audit.read":
    "sha256:1584fcf232fdb8c21fed20478791f8199015b39805c3f7e53ffccc801ef3a9e1",
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

  it("pins 18 separated operation schemas and explicit request/response limits", () => {
    expect(HOST_RPC_OPERATIONS).toHaveLength(18);
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
    ).toHaveLength(18);

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
