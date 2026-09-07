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
    "sha256:3ee255a3d28dae86a5bc984bc8080f1b38a57826f4b67740eec8fb825770128b",
  "session.execute":
    "sha256:6823545b5f7299f5303e9d9e9cc9f8b638a61d8003dcc5156421febcad4a2528",
  "session.read":
    "sha256:aa7904d06f40a3629441219cfc16fd0d5bc0f5f50511e88e6f739aaf5f668c91",
  "session.read-events":
    "sha256:11301a937f70c946b90918669089a4cac298a273c222940d0fe4801a7d52b2ba",
  "workspace.initialize":
    "sha256:7e1e40550871780835363e98ed781a99238e014b4ed676d71afd5a6776d21244",
  "workspace.execute":
    "sha256:6ed3fd228872aebdae93ca3b9b6e55de3081c8f2a163661c52b975c59ae46485",
  "workspace.lookup-invocation":
    "sha256:7d6463ba3559400f716bb3935eaaedc4ebbe1cdd9ac4ad967e82a44effcefe25",
  "user.initialize":
    "sha256:516a1d7b448438c29424003daecae8226b17519e223c04bf019516b598deeff2",
  "user.execute":
    "sha256:4da1dc3928344268f9b6b1371265aba7123d285b15be0279359619e69c069231",
  "user.read":
    "sha256:b4664353f8ac1f98d590f52548952d90654c900778c133e264da555bf7919d8d",
  "extension-state.initialize":
    "sha256:9c00ea2c454bcea962e1a6e264fac55945e47499369e1be772e068ae05bd39d6",
  "extension-state.execute":
    "sha256:b46c54f6e2d2ffb6369edd3fe374231847e35fbbb043f76e8cfc3d5fe2f45044",
  "extension-state.read":
    "sha256:13e07665ab2ad3e71cc4a135940551ac3dfb6a110227a11d55f0a922216f94e7",
  "capability-generation.initialize":
    "sha256:1f724eb596301eeda6bd78fb998c28cfca496e12176009eea501374260409ac9",
  "capability-generation.execute":
    "sha256:65927b95d07777b37f9685fe9e111207ff19d27f68781bae0b49c41edecec712",
  "capability-generation.assert-current":
    "sha256:1b3d23a63c604f0a726f7eb58d9515ab5a2d407eac292b9e713cd395d80f9a02",
  "audit.initialize":
    "sha256:b77c231650e9aa3d2d9c99a28ba21335ee181316e265f98b12753c2a7fdbc474",
  "audit.execute":
    "sha256:1d10a5cc24770da55e4372e38ee401acbeac68a7c2aea0246407128892c2cb05",
  "audit.read":
    "sha256:a4204d1d11483e8ece179840834c9fe0fff2f87a339c77beb120426eeaa16895",
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
