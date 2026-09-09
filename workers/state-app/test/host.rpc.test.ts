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
    "sha256:8852b3a4ae79623ae45fdd9cd3a0f1719fa68ce8f9547806e9930f68d5bd150c",
  "session.execute":
    "sha256:91d6843e1206ae3464fce8b3fead4588b74ff9e0d40aafd8dd68cb76e7fc7551",
  "session.read":
    "sha256:88afdb3fc3cc3b807eee91e5abb78bfc129f108edaaf6c71049b72a87484090a",
  "session.read-events":
    "sha256:9d5c8e213c2701b5072c5f849fad927e23369bfd2c9aa11c14ad3b36e96a5315",
  "workspace.initialize":
    "sha256:3feaa535fb581127c2ad976f641eca69132b7d39efc814e6c85a01ac281c8d03",
  "workspace.execute":
    "sha256:da67106c98b21d83162fd559831b528b9c3ccbabb3d3f4e4c4b758debb57d51a",
  "workspace.lookup-invocation":
    "sha256:fd4184f8edd97cc3a840b8a1591dda8a2c0c277a762a46af9b226b4aa4252019",
  "user.initialize":
    "sha256:d107efa59c0cf792ecf24eca68789fc43b997524d909fbe0a206b53c2f2d9bd3",
  "user.execute":
    "sha256:7c2bcfb200c5f60577b992952ffc321cd6f65eaead33ff30605a804fe3d6dd55",
  "user.read":
    "sha256:f1955478d14fee1a0b0dd24845ff22b7a4d51cb0a9a1509a6dc5b40f5e5283d2",
  "extension-state.initialize":
    "sha256:ab94e07b77ede051d1785f5948325f119a3d37bf4332bceb3234d7aea90c7f0a",
  "extension-state.execute":
    "sha256:a9d3a34e9947e0a604af79cc9279e6d9f4f68ed01997b5e07a169b91f98cc1d4",
  "extension-state.read":
    "sha256:b645e4e322cc5f31ac54f93650647b5b047f66405d4902a033e860937d4281b0",
  "capability-generation.initialize":
    "sha256:8edadd748e57ea7ea1da14f3ffe3b2a2e897d5ed53d1104cf022d7ace1fea1f2",
  "capability-generation.execute":
    "sha256:df99751ed70d1d10e2b39ab8861d8e89e70600c9f8b6ec7c3bcd4d325a3026d2",
  "capability-generation.assert-current":
    "sha256:c07f4c0c464c26f8f9c4fd7abd8ed442edeec8dd648e49f11aef31341a6ebe79",
  "audit.initialize":
    "sha256:4776972e958758dad3f324bf9c2b35f9568a86d8136ab1c1676eea53cacd947f",
  "audit.execute":
    "sha256:528f84c439f1aff20bc75dc54124b04bdf75f208efe784ac68d5c72aba6f02b1",
  "audit.read":
    "sha256:d959d66f6d49f84cad69b819b1b5f5ca329d2f1378c7756b967604802f99c831",
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
