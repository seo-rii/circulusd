import { describe, expect, it } from "vitest";

import {
  LowLevelPiAgentEngine,
  createOpaqueTurnAuthority,
  type ExtensionRegistration,
} from "../src/index.ts";
import { genesis, identity, scriptedCore, successSettlement } from "./helpers.ts";

const authority = () => createOpaqueTurnAuthority(new Uint8Array([9]));

describe("deterministic extension lifecycle", () => {
  it("seals the hook graph synchronously when the first step is admitted", async () => {
    const core = scriptedCore(() => ({ kind: "checkpoint_only", state: null }));
    const engine = new LowLevelPiAgentEngine(identity("session_step_seals_hooks"), core.factory);
    const pending = engine.step({
      authority: authority(),
      checkpoint: await genesis(engine),
    });

    expect(() =>
      engine.registerExtension({
        manifest: { id: "late", priority: 1, tools: [], patchableFields: {} },
        create: () => ({}),
      }),
    ).toThrowError(expect.objectContaining({ code: "HOOK_REGISTRY_FROZEN" }));
    await expect(pending).resolves.toMatchObject({ kind: "checkpoint" });
  });

  it("rejects manifest collection accessors without executing their getters", () => {
    const core = scriptedCore(() => ({ kind: "checkpoint_only", state: null }));
    const engine = new LowLevelPiAgentEngine(identity("session_manifest_accessor"), core.factory);
    let getterCalls = 0;
    const tools: string[] = [];
    Object.defineProperty(tools, "0", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return "hostile";
      },
    });

    expect(() =>
      engine.registerExtension({
        manifest: { id: "hostile", priority: 1, tools, patchableFields: {} },
        create: () => ({}),
      }),
    ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
    expect(getterCalls).toBe(0);
  });

  it("orders hooks by priority then extension id and freezes registration", async () => {
    const calls: string[] = [];
    const registration = (id: string, priority: number): ExtensionRegistration => ({
      manifest: {
        id,
        priority,
        tools: [],
        patchableFields: {
          beforeModelRequest: ["payload"],
          beforeToolCall: ["payload"],
          afterModelResponse: ["result"],
          afterToolCall: ["result"],
        },
      },
      create: () => ({
        async initialize() {
          calls.push(`${id}:initialize`);
        },
        async beforeAgentStart() {
          calls.push(`${id}:beforeAgentStart`);
        },
        async beforeTurn() {
          calls.push(`${id}:beforeTurn`);
        },
        async beforeModelRequest(event) {
          calls.push(`${id}:beforeModelRequest`);
          expect(event.request.payload).toMatchObject({ original: true });
          return { payload: { original: true, touchedBy: id } };
        },
        async afterModelResponse(event) {
          calls.push(`${id}:afterModelResponse`);
          expect(event.result).toMatchObject({ model: true });
          return { result: { model: true, touchedBy: id } };
        },
        async beforeToolCall(event) {
          calls.push(`${id}:beforeToolCall`);
          expect(event.request.payload).toMatchObject({ original: true });
          return { payload: { original: true, touchedBy: id } };
        },
        async afterToolCall(event) {
          calls.push(`${id}:afterToolCall`);
          expect(event.result).toMatchObject({ tool: true });
          return { result: { tool: true, touchedBy: id } };
        },
        async afterTurn() {
          calls.push(`${id}:afterTurn`);
        },
      }),
    });
    const core = scriptedCore((context, call) => {
      if (call === 1) {
        return {
          kind: "model_request",
          state: { phase: "model" },
          request: {
            service: "model",
            operation: "complete",
            replayPolicy: "safe",
            payload: { original: true },
          },
        };
      }
      if (call === 2) {
        expect(context.input).toMatchObject({
          kind: "effect_settlement",
          settlement: { kind: "success", result: { model: true, touchedBy: "ext-z" } },
        });
        return {
          kind: "tool_requests",
          state: { phase: "tool" },
          requests: [
            {
              service: "external-tool",
              operation: "lookup",
              replayPolicy: "safe",
              payload: { original: true },
            },
          ],
        };
      }
      expect(context.input).toMatchObject({
        kind: "tool_settlements",
        results: [
          { settlement: { kind: "success", result: { tool: true, touchedBy: "ext-z" } } },
        ],
      });
      return { kind: "turn_complete", state: { phase: "done" }, result: { ok: true } };
    });
    const engine = new LowLevelPiAgentEngine(identity("session_hooks"), core.factory);
    engine.registerExtension(registration("ext-b", 10));
    engine.registerExtension(registration("ext-z", 20));
    engine.registerExtension(registration("ext-a", 10));
    await engine.initialize();
    expect(calls).toEqual([
      "ext-a:initialize",
      "ext-b:initialize",
      "ext-z:initialize",
      "ext-a:beforeAgentStart",
      "ext-b:beforeAgentStart",
      "ext-z:beforeAgentStart",
    ]);
    expect(() => engine.registerExtension(registration("late", 0))).toThrowError(
      expect.objectContaining({ code: "HOOK_REGISTRY_FROZEN" }),
    );

    const model = await engine.step({ authority: authority(), checkpoint: await genesis(engine) });
    if (model.kind !== "effect_request") throw new Error("expected model request");
    expect(model.request.payload).toEqual({ original: true, touchedBy: "ext-z" });
    const tool = await engine.step({
      authority: authority(),
      checkpoint: model.checkpoint,
      settlement: successSettlement(model.request.requestDigest, { model: true }),
    });
    if (tool.kind !== "effect_request") throw new Error("expected tool request");
    expect(tool.request.payload).toEqual({ original: true, touchedBy: "ext-z" });
    const complete = await engine.step({
      authority: authority(),
      checkpoint: tool.checkpoint,
      settlement: successSettlement(tool.request.requestDigest, { tool: true }),
    });
    expect(complete.kind).toBe("turn_complete");
    expect(calls.slice(6)).toEqual([
      "ext-a:beforeTurn",
      "ext-b:beforeTurn",
      "ext-z:beforeTurn",
      "ext-a:beforeModelRequest",
      "ext-b:beforeModelRequest",
      "ext-z:beforeModelRequest",
      "ext-a:afterModelResponse",
      "ext-b:afterModelResponse",
      "ext-z:afterModelResponse",
      "ext-a:beforeToolCall",
      "ext-b:beforeToolCall",
      "ext-z:beforeToolCall",
      "ext-a:afterToolCall",
      "ext-b:afterToolCall",
      "ext-z:afterToolCall",
      "ext-a:afterTurn",
      "ext-b:afterTurn",
      "ext-z:afterTurn",
    ]);
  });

  it("rejects duplicate tool registration before the runtime becomes ready", async () => {
    const core = scriptedCore(() => ({ kind: "checkpoint_only", state: null }));
    const engine = new LowLevelPiAgentEngine(identity("session_collision"), core.factory);
    for (const id of ["ext-a", "ext-b"]) {
      engine.registerExtension({
        manifest: { id, priority: 1, tools: ["duplicate"], patchableFields: {} },
        create: () => ({}),
      });
    }
    await expect(engine.initialize()).rejects.toMatchObject({ code: "TOOL_NAME_COLLISION" });
  });

  it("constructs fresh extension instances for two sessions", async () => {
    const registration: ExtensionRegistration = {
      manifest: {
        id: "counter",
        priority: 1,
        tools: [],
        patchableFields: { beforeModelRequest: ["payload"] },
      },
      create: () => {
        let turns = 0;
        return {
          async beforeTurn() {
            turns += 1;
          },
          async beforeModelRequest(event) {
            expect(event.request.payload).toEqual({});
            return { payload: { turns } };
          },
        };
      },
    };
    const make = (sessionId: string) => {
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
      const engine = new LowLevelPiAgentEngine(identity(sessionId), core.factory);
      engine.registerExtension(registration);
      return engine;
    };
    const left = make("session_left");
    const right = make("session_right");
    const [leftResult, rightResult] = await Promise.all([
      left.step({ authority: authority(), checkpoint: await genesis(left) }),
      right.step({ authority: authority(), checkpoint: await genesis(right) }),
    ]);
    if (leftResult.kind !== "effect_request" || rightResult.kind !== "effect_request") {
      throw new Error("expected model requests");
    }
    expect(leftResult.request.payload).toEqual({ turns: 1 });
    expect(rightResult.request.payload).toEqual({ turns: 1 });
  });
});
