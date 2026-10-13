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
    "sha256:9963f367c371c9bc5df4154e29602bf832f7b1bf1f976c5617028a347111f1e3",
  "session.execute":
    "sha256:5f9c46ee54e71d97d57295235810a70d70b1579fdcb077ede948c3e680405845",
  "session.read":
    "sha256:a0fc87ce500354938564ad85dc06d019502e1a24eb19d0185e81c11b7f43016f",
  "session.read-blob":
    "sha256:7f91a8302896ad3260e47d08d17f95934e377f41860d1eb83c6170e4165767ec",
  "session.read-events":
    "sha256:b8b43aaad3084312d497075227a0f7356d550db9efac5c008c5a346124191707",
  "workspace.initialize":
    "sha256:0a6f7f24f4ce6887b64526b1584caff6b8d846513d91f935d9a2cf9b0b3e9c9c",
  "workspace.execute":
    "sha256:d48de89fc8c0cf2ce59273945294d39dbf8a56858ceeaf2e68e52050294a6685",
  "workspace.lookup-invocation":
    "sha256:18cf12409fe6cd0d73204f291573ebdcc2c739655eaf033ab244716571860a4c",
  "user.initialize":
    "sha256:b06cbbf9fa715d5bcccb377b0706aa0d0aa007c3d0aa70a2751f223a220b1dbc",
  "user.execute":
    "sha256:d4adb26b95d76bbd5ce51ebaac21f22f7e4da51319547298c66a546d3f5f651b",
  "user.read":
    "sha256:d4661a53f2680831d8dcbbdfcb3e4a344434b3d46628a286b9e8391e1e15f99d",
  "extension-state.initialize":
    "sha256:2c95930bcc5b20ccf61281bf9f699d36b0b2e71a9a435e2d7203bf1931fb9029",
  "extension-state.execute":
    "sha256:4d73ec2d69dbc13038ac41b115940a7b776f01138feb6768acafe5cf165677f0",
  "extension-state.read":
    "sha256:2ce05d646bb79d7cf967476dbefca0117b369c3d1bf0c6ecfb1823febf32fe0a",
  "capability-generation.initialize":
    "sha256:bda36c65b11367104a6823c2eb62664fdfb206684149d97e834ba8dbf0290c89",
  "capability-generation.execute":
    "sha256:35b01e0af98208d150d199fdc9fd1b3e098cbd20badaf91d104f8c90781cb5e3",
  "capability-generation.assert-current":
    "sha256:134bddc189cbfb0a151acbd723516f51cee28f13f23434b5a3017f27989b0241",
  "audit.initialize":
    "sha256:806c7da7bf07da52a9cb97af0171edd98abb910a22a09f225a7f7dd7c2b8b52e",
  "audit.execute":
    "sha256:556d65ae9c05413e93ebbef15f21e9b1beb02eaf8d855ec45550ecec9078a3cb",
  "audit.read":
    "sha256:78e0e4bd6181be5c1c1ec77b2cbee782b07ce1728e0716cdf384ce9ac51231c0",
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

  it("pins 20 separated operation schemas and explicit request/response limits", () => {
    expect(HOST_RPC_OPERATIONS).toHaveLength(20);
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
    ).toHaveLength(20);

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
