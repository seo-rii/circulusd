import { describe, expect, it } from "vitest";

import {
  PROTOCOL_MAJOR,
  PROTOCOL_MINOR,
  PROTOCOL_NAME,
  ProtocolValidationError,
  assertCheckpointPayloadDigest,
  digestBytes,
  isPassingConformanceStatus,
  parseAgentCheckpoint,
  parseConformanceStatus,
  parseDispatchPermitClaims,
  parseEffectClaim,
  parseEngineStepResult,
  parseNormalizedValue,
  parseRpcEnvelope,
  validateAgentCheckpoint,
  validateEngineStepResult,
} from "../src/index.ts";

const ZERO_DIGEST = `sha256:${"0".repeat(64)}`;
const ONE_DIGEST = `sha256:${"1".repeat(64)}`;
const PAYLOAD_DIGEST =
  "sha256:039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81";

function genesisCheckpoint(): Record<string, unknown> {
  return {
    kind: "genesis",
    engineKind: "low-level",
    adapterAbiVersion: 1,
    checkpointSchemaVersion: 1,
    runtimeRevisionDigest: ZERO_DIGEST,
    sessionId: "sess_01",
    turnId: "turn_01",
    checkpointSequence: 0,
    predecessorDigest: null,
    payloadEncoding: "opaque-v1",
    payloadBytes: new Uint8Array([1, 2, 3]),
    payloadDigest: PAYLOAD_DIGEST,
  };
}

function engineCheckpoint(): Record<string, unknown> {
  return {
    ...genesisCheckpoint(),
    kind: "engine",
    checkpointSequence: 1,
    predecessorDigest: ONE_DIGEST,
  };
}

function effectClaim(): Record<string, unknown> {
  return {
    tenantId: "tenant_01",
    userId: "user_01",
    sessionId: "sess_01",
    turnId: "turn_01",
    effectId: "effect_01",
    invocationId: "invocation_01",
    requestDigest: ZERO_DIGEST,
    service: "executor",
    operation: "spawn",
    replayPolicy: "idempotency-key",
    parentOperationId: "tool_call_01",
    ordinal: 0,
  };
}

describe("protocol constants and RPC envelopes", () => {
  it("pins the v1alpha1 identity", () => {
    expect(PROTOCOL_NAME).toBe("circulus.v1alpha1");
    expect(PROTOCOL_MAJOR).toBe(1);
    expect(PROTOCOL_MINOR).toBe(0);
  });

  it("validates and copies a normalized RPC envelope", () => {
    const input = {
      protocol: PROTOCOL_NAME,
      major: 1,
      minor: 0,
      schemaDigest: ZERO_DIGEST,
      requestId: "request_01",
      payload: { greeting: "A\u030A", bytes: new Uint8Array([7]) },
    };

    const parsed = parseRpcEnvelope(input, parseNormalizedValue, {
      expectedSchemaDigest: ZERO_DIGEST,
    });
    expect(parsed.payload).toEqual({ greeting: "Å", bytes: new Uint8Array([7]) });
    expect(parsed.payload).not.toBe(input.payload);
  });

  it("fails closed on incompatible versions, schema, and unknown fields", () => {
    const valid = {
      protocol: PROTOCOL_NAME,
      major: 1,
      minor: 0,
      schemaDigest: ZERO_DIGEST,
      requestId: "request_01",
      payload: null,
    };

    expect(() =>
      parseRpcEnvelope({ ...valid, major: 2 }, parseNormalizedValue),
    ).toThrow(/major/);
    expect(() =>
      parseRpcEnvelope({ ...valid, minor: 1 }, parseNormalizedValue),
    ).toThrow(/minor/);
    expect(() =>
      parseRpcEnvelope(valid, parseNormalizedValue, {
        expectedSchemaDigest: ONE_DIGEST,
      }),
    ).toThrow(/schemaDigest/);
    expect(() =>
      parseRpcEnvelope({ ...valid, surprise: true }, parseNormalizedValue),
    ).toThrow(/unknown field/);
  });

  it("rejects class instances and request payloads beyond limits", () => {
    class Payload {
      readonly value = 1;
    }

    const envelope = {
      protocol: PROTOCOL_NAME,
      major: 1,
      minor: 0,
      schemaDigest: ZERO_DIGEST,
      requestId: "request_01",
      payload: new Payload(),
    };
    expect(() => parseRpcEnvelope(envelope, parseNormalizedValue)).toThrow(
      /plain object/,
    );
    expect(() =>
      parseRpcEnvelope(
        { ...envelope, payload: "too large" },
        parseNormalizedValue,
        { maxEncodedBytes: 16 },
      ),
    ).toThrow(/size/);
    expect(() =>
      parseRpcEnvelope(
        { ...envelope, payload: Array.from({ length: 50 }, () => null) },
        parseNormalizedValue,
        { maxItems: 20 },
      ),
    ).toThrow(/item limit/);
  });
});

describe("checkpoint protocol", () => {
  it("validates genesis and sequenced engine checkpoints", async () => {
    const genesis = parseAgentCheckpoint(genesisCheckpoint());
    expect(genesis.kind).toBe("genesis");
    expect(genesis.payloadBytes).toEqual(new Uint8Array([1, 2, 3]));
    await expect(assertCheckpointPayloadDigest(genesis)).resolves.toBeUndefined();

    const engine = parseAgentCheckpoint(engineCheckpoint());
    expect(engine.kind).toBe("engine");
    expect(engine.predecessorDigest).toBe(ONE_DIGEST);
  });

  it("rejects malformed sequence/predecessor pairs and unknown fields", () => {
    expect(() =>
      parseAgentCheckpoint({ ...genesisCheckpoint(), checkpointSequence: 1 }),
    ).toThrow(/checkpointSequence/);
    expect(() =>
      parseAgentCheckpoint({ ...engineCheckpoint(), predecessorDigest: null }),
    ).toThrow(/predecessorDigest/);
    expect(() =>
      parseAgentCheckpoint({ ...engineCheckpoint(), extra: "field" }),
    ).toThrow(/unknown field/);
  });

  it("rejects mutable-lookalike and mismatched opaque payloads", async () => {
    expect(() =>
      parseAgentCheckpoint({ ...genesisCheckpoint(), payloadBytes: [1, 2, 3] }),
    ).toThrow(/Uint8Array/);
    const checkpoint = parseAgentCheckpoint({
      ...genesisCheckpoint(),
      payloadDigest: ZERO_DIGEST,
    });
    await expect(assertCheckpointPayloadDigest(checkpoint)).rejects.toThrow(
      /payloadDigest/,
    );
    await expect(
      validateAgentCheckpoint({ ...genesisCheckpoint(), payloadDigest: ZERO_DIGEST }),
    ).rejects.toThrow(/payloadDigest/);
    await expect(validateAgentCheckpoint(genesisCheckpoint())).resolves.toMatchObject({
      kind: "genesis",
      checkpointSequence: 0,
    });
    await expect(digestBytes(new Uint8Array([1, 2, 3]))).resolves.toBe(
      PAYLOAD_DIGEST,
    );
  });
});

describe("effect and dispatch claims", () => {
  it("validates an effect claim and a generation-bound permit", () => {
    expect(parseEffectClaim(effectClaim())).toMatchObject({
      service: "executor",
      replayPolicy: "idempotency-key",
      ordinal: 0,
    });

    expect(
      parseDispatchPermitClaims({
        ...effectClaim(),
        dispatchAttempt: 1,
        turnLeaseGeneration: 4,
        placementGeneration: 5,
        sandboxGeneration: 6,
        authorizationGeneration: 7,
        providerRouteDigest: ONE_DIGEST,
        deadline: 1_800_000_000_000,
      }),
    ).toMatchObject({
      dispatchAttempt: 1,
      authorizationGeneration: 7,
      providerRouteDigest: ONE_DIGEST,
    });
  });

  it("requires paired composite identity and every permit generation", () => {
    const claim = effectClaim();
    delete claim.ordinal;
    expect(() => parseEffectClaim(claim)).toThrow(/parentOperationId.*ordinal/);

    const permit = {
      ...effectClaim(),
      dispatchAttempt: 0,
      turnLeaseGeneration: 4,
      placementGeneration: 5,
      sandboxGeneration: 6,
      authorizationGeneration: 7,
      providerRouteDigest: ONE_DIGEST,
      deadline: 1_800_000_000_000,
    };
    expect(() => parseDispatchPermitClaims(permit)).toThrow(/dispatchAttempt/);
    const { sandboxGeneration: _omitted, ...withoutSandboxGeneration } = permit;
    expect(() => parseDispatchPermitClaims(withoutSandboxGeneration)).toThrow(
      /sandboxGeneration/,
    );
  });

  it("requires an exact non-zero provider route digest on dispatch permits", () => {
    const permit = {
      ...effectClaim(),
      dispatchAttempt: 1,
      turnLeaseGeneration: 4,
      placementGeneration: 5,
      sandboxGeneration: 6,
      authorizationGeneration: 7,
      providerRouteDigest: ONE_DIGEST,
      deadline: 1_800_000_000_000,
    };

    const parsed = parseDispatchPermitClaims(permit);
    expect(parsed.providerRouteDigest).toBe(ONE_DIGEST);

    const { providerRouteDigest: _omitted, ...withoutProviderRouteDigest } = permit;
    expect(() => parseDispatchPermitClaims(withoutProviderRouteDigest)).toThrow(
      /providerRouteDigest/,
    );
    expect(() =>
      parseDispatchPermitClaims({ ...permit, providerRouteDigest: ZERO_DIGEST })
    ).toThrow(/providerRouteDigest/);
    expect(() =>
      parseDispatchPermitClaims({ ...permit, providerRouteDigest: "sha256:not-a-digest" })
    ).toThrow(/providerRouteDigest/);

    const { providerRouteDigest: _relabelled, ...relabeledPermit } = permit;
    expect(() =>
      parseDispatchPermitClaims({
        ...relabeledPermit,
        providerRouteHash: ONE_DIGEST,
      })
    ).toThrow(/providerRouteDigest|providerRouteHash/);
  });
});

describe("bounded engine results", () => {
  it("validates every durable boundary without retaining caller bytes", () => {
    const checkpoint = engineCheckpoint();
    const effectRequest = parseEngineStepResult({
      kind: "effect_request",
      checkpoint,
      request: {
        service: "model",
        operation: "complete",
        replayPolicy: "safe",
        requestDigest: ZERO_DIGEST,
        payload: { promptRef: "blob_01" },
      },
    });
    expect(effectRequest.kind).toBe("effect_request");
    expect(effectRequest.checkpoint.payloadBytes).not.toBe(checkpoint.payloadBytes);

    expect(
      parseEngineStepResult({ kind: "checkpoint", checkpoint }).kind,
    ).toBe("checkpoint");
    expect(
      parseEngineStepResult({
        kind: "turn_complete",
        checkpoint,
        result: { messageRef: "event_01" },
      }).kind,
    ).toBe("turn_complete");
    expect(
      parseEngineStepResult({
        kind: "turn_error",
        checkpoint,
        error: { code: "MODEL_FAILED", message: "failed", retryable: true },
      }).kind,
    ).toBe("turn_error");
  });

  it("rejects unknown result and nested request fields", () => {
    expect(() =>
      parseEngineStepResult({
        kind: "checkpoint",
        checkpoint: engineCheckpoint(),
        request: {},
      }),
    ).toThrow(/unknown field/);
    expect(() =>
      parseEngineStepResult({
        kind: "effect_request",
        checkpoint: engineCheckpoint(),
        request: {
          service: "model",
          operation: "complete",
          replayPolicy: "safe",
          requestDigest: ZERO_DIGEST,
          payload: null,
          hidden: true,
        },
      }),
    ).toThrow(/unknown field/);
  });

  it("validates the checkpoint payload digest before trusting a step boundary", async () => {
    const result = {
      kind: "checkpoint",
      checkpoint: { ...engineCheckpoint(), payloadDigest: ZERO_DIGEST },
    };
    await expect(validateEngineStepResult(result)).rejects.toThrow(/payloadDigest/);
    await expect(
      validateEngineStepResult({ kind: "checkpoint", checkpoint: engineCheckpoint() }),
    ).resolves.toMatchObject({ kind: "checkpoint" });
  });
});

describe("conformance status", () => {
  it("preserves PASS/FAIL/UNAVAILABLE(reason)/NOT_RUN exactly", () => {
    expect(parseConformanceStatus({ status: "PASS" })).toEqual({ status: "PASS" });
    expect(parseConformanceStatus({ status: "FAIL" })).toEqual({ status: "FAIL" });
    expect(parseConformanceStatus({ status: "NOT_RUN" })).toEqual({
      status: "NOT_RUN",
    });
    expect(
      parseConformanceStatus({ status: "UNAVAILABLE", reason: "no /dev/kvm" }),
    ).toEqual({ status: "UNAVAILABLE", reason: "no /dev/kvm" });
    expect(isPassingConformanceStatus({ status: "PASS" })).toBe(true);
    expect(isPassingConformanceStatus({ status: "NOT_RUN" })).toBe(false);
  });

  it("rejects softened or embellished statuses", () => {
    expect(() => parseConformanceStatus({ status: "SKIPPED" })).toThrow(
      ProtocolValidationError,
    );
    expect(() =>
      parseConformanceStatus({ status: "PASS", reason: "mock passed" }),
    ).toThrow(/unknown field/);
    expect(() =>
      parseConformanceStatus({ status: "UNAVAILABLE", reason: "" }),
    ).toThrow(/reason/);
  });
});
