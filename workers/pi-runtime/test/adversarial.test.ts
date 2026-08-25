import { digestBytes, encodeCanonicalCbor } from "@circulusd/protocol-types";
import { describe, expect, it, vi } from "vitest";

import {
  LowLevelPiAgentEngine,
  createOpaqueTurnAuthority,
  type PiPlatformExtension,
} from "../src/index.ts";
import { genesis, identity, scriptedCore } from "./helpers.ts";

const authority = () => createOpaqueTurnAuthority(new Uint8Array([13]));

describe("hostile Pi boundary inputs", () => {
  it("rejects a digest-valid checkpoint with an invalid exact payload and releases the step claim", async () => {
    const core = scriptedCore(() => ({ kind: "checkpoint_only", state: null }));
    const engine = new LowLevelPiAgentEngine(identity("session_checkpoint_attack"), core.factory);
    const valid = await genesis(engine);
    const payloadBytes = encodeCanonicalCbor({});
    const forged = {
      ...valid,
      payloadBytes,
      payloadDigest: await digestBytes(payloadBytes),
    };

    await expect(engine.step({ authority: authority(), checkpoint: forged })).rejects.toMatchObject({
      code: "INVALID_CHECKPOINT",
    });
    await expect(engine.step({ authority: authority(), checkpoint: valid })).resolves.toMatchObject({
      kind: "checkpoint",
    });
    expect(core.contexts).toHaveLength(1);
  });

  it("round-trips byte-valued input through canonical checkpoint CBOR", async () => {
    const core = scriptedCore((context) => {
      expect(context.input).toEqual({
        kind: "turn_start",
        input: { blob: new Uint8Array([0, 127, 255]) },
      });
      return { kind: "checkpoint_only", state: { blob: new Uint8Array([9, 8, 7]) } };
    });
    const engine = new LowLevelPiAgentEngine(identity("session_bytes"), core.factory);
    const first = await engine.step({
      authority: authority(),
      checkpoint: await genesis(engine, "turn_bytes", {
        blob: new Uint8Array([0, 127, 255]),
      }),
    });
    expect(first.kind).toBe("checkpoint");
  });

  it.each([
    {
      name: "unknown field",
      output: () => ({ payload: {}, authority: "forged" }),
    },
    {
      name: "oversized value",
      output: () => ({ payload: { text: "x".repeat(1_000) } }),
    },
  ])("rejects extension patch $name", async ({ output }) => {
    const core = scriptedCore(() => ({
      kind: "model_request",
      state: null,
      request: {
        service: "model",
        operation: "complete",
        replayPolicy: "safe",
        payload: {},
      },
    }));
    const engine = new LowLevelPiAgentEngine(identity(`session_extension_${output.name}`), core.factory, {
      budgets: { maxExtensionOutputBytes: 128 },
    });
    engine.registerExtension({
      manifest: {
        id: "hostile",
        priority: 1,
        tools: [],
        patchableFields: { beforeModelRequest: ["payload"] },
      },
      create: () => ({ beforeModelRequest: async () => output() }),
    });
    await expect(
      engine.step({ authority: authority(), checkpoint: await genesis(engine) }),
    ).resolves.toMatchObject({
      kind: "turn_error",
      error: { code: "EXTENSION_OUTPUT_INVALID" },
    });
  });

  it("rejects an accessor patch without invoking the accessor", async () => {
    const getter = vi.fn(() => ({}));
    const extension: PiPlatformExtension = {
      async beforeModelRequest() {
        const patch = {};
        Object.defineProperty(patch, "payload", { enumerable: true, get: getter });
        return patch;
      },
    };
    const core = scriptedCore(() => ({
      kind: "model_request",
      state: null,
      request: {
        service: "model",
        operation: "complete",
        replayPolicy: "safe",
        payload: {},
      },
    }));
    const engine = new LowLevelPiAgentEngine(identity("session_accessor"), core.factory);
    engine.registerExtension({
      manifest: {
        id: "accessor",
        priority: 1,
        tools: [],
        patchableFields: { beforeModelRequest: ["payload"] },
      },
      create: () => extension,
    });
    const result = await engine.step({ authority: authority(), checkpoint: await genesis(engine) });
    expect(result).toMatchObject({
      kind: "turn_error",
      error: { code: "EXTENSION_OUTPUT_INVALID" },
    });
    expect(getter).not.toHaveBeenCalled();
  });

  it("does not emit a partial assistant stream when the event budget is invalid", async () => {
    const emitDelta = vi.fn();
    const core = scriptedCore(() => ({
      kind: "checkpoint_only",
      state: null,
      assistantDeltas: [{ n: 1 }, { n: 2 }],
    }));
    const engine = new LowLevelPiAgentEngine(identity("session_events"), core.factory, {
      budgets: { maxEventsPerStep: 2 },
    });
    const result = await engine.step({
      authority: authority(),
      checkpoint: await genesis(engine),
      emitDelta,
    });
    expect(result).toMatchObject({
      kind: "turn_error",
      error: { code: "EVENT_BUDGET_EXCEEDED" },
    });
    expect(emitDelta).not.toHaveBeenCalled();
  });
});
