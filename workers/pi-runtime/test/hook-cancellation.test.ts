import { describe, expect, it } from "vitest";

import { BoundaryFault } from "../src/errors.ts";
import { HookDispatcher } from "../src/lifecycle.ts";
import { LowLevelPiAgentEngine, createOpaqueTurnAuthority } from "../src/index.ts";
import { genesis, identity, scriptedCore } from "./helpers.ts";

const hooks = [
  "beforeTurn", "afterTurn", "beforeModelRequest", "beforeToolCall",
  "afterModelResponse", "afterToolCall",
] as const;

function dispatch(dispatcher: HookDispatcher, hook: typeof hooks[number], signal: AbortSignal) {
  const request = {
    service: "model" as const,
    operation: "complete",
    replayPolicy: "safe" as const,
    payload: null,
    requestDigest: `sha256:${"0".repeat(64)}` as const,
  };
  switch (hook) {
    case "beforeTurn":
    case "afterTurn":
      return dispatcher[hook]("turn_01", null, signal);
    case "beforeModelRequest":
    case "beforeToolCall":
      return dispatcher[hook]("turn_01", request, signal);
    case "afterModelResponse":
    case "afterToolCall":
      return dispatcher[hook]("turn_01", request, null, signal);
  }
}

describe("extension hook cancellation", () => {
  it.each(hooks)("does not start a later %s hook after cancellation", async (hook) => {
    const dispatcher = new HookDispatcher(identity("session_hook_cancel"), 1024);
    const entered = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    const calls: string[] = [];
    for (const id of ["first", "second"]) {
      dispatcher.register({
        manifest: { id, priority: 0, tools: [], patchableFields: {} },
        create: () => ({
          [hook]: async () => {
            calls.push(id);
            if (id === "first") {
              entered.resolve();
              await release.promise;
            }
          },
        }),
      });
    }
    await dispatcher.initialize();
    const controller = new AbortController();
    const pending = dispatch(dispatcher, hook, controller.signal);
    await entered.promise;
    const reason = new BoundaryFault("STEP_TIMEOUT", "step timed out");
    controller.abort(reason);
    release.resolve();
    await expect(pending).rejects.toBe(reason);
    expect(calls).toEqual(["first"]);
    await expect(dispatch(dispatcher, hook, controller.signal)).rejects.toBe(reason);
    expect(calls).toEqual(["first"]);
  });

  it("does not start another hook after the engine commits to an aborted turn", async () => {
    const entered = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    const calls: string[] = [];
    const core = scriptedCore(() => ({ kind: "turn_complete", state: null, result: null }));
    const engine = new LowLevelPiAgentEngine(identity("session_aborted_hooks"), core.factory);
    for (const id of ["first", "second"]) {
      engine.registerExtension({
        manifest: { id, priority: 0, tools: [], patchableFields: {} },
        create: () => ({
          async beforeTurn() {
            calls.push(id);
            if (id === "first") {
              entered.resolve();
              await release.promise;
            }
          },
        }),
      });
    }
    const checkpoint = await genesis(engine);
    const pending = engine.step({
      authority: createOpaqueTurnAuthority(new Uint8Array([1])), checkpoint,
    });
    await entered.promise;
    await engine.abortTurn(checkpoint.turnId);
    await expect(pending).resolves.toMatchObject({
      kind: "turn_error", error: { code: "TURN_ABORTED" },
    });
    release.resolve();
    // Let the suspended hook and dispatcher continuation finish.
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(calls).toEqual(["first"]);
    expect(core.contexts).toHaveLength(0);
  });
});
