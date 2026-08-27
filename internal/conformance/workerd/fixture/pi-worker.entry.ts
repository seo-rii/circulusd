import {
  LowLevelPiAgentEngine,
  createOpaqueTurnAuthority,
  type AgentCoreFactory,
  type ExtensionRegistration,
} from "../../../../workers/pi-runtime/src/index.ts";

let counter = 0;

async function denied(operation: () => Promise<unknown>): Promise<boolean> {
  try {
    await operation();
    return false;
  } catch {
    return true;
  }
}

async function runAgentTurn(): Promise<{
  readonly completed: boolean;
  readonly modelRequests: number;
  readonly toolRequests: number;
  readonly hooks: readonly string[];
}> {
  const hooks: string[] = [];
  let modelRequests = 0;
  let toolRequests = 0;
  const coreFactory: AgentCoreFactory = () => ({
    async advance(context) {
      if (context.input.kind === "turn_start") {
        modelRequests += 1;
        return {
          kind: "model_request",
          state: { phase: "model" },
          request: {
            service: "model",
            operation: "complete",
            replayPolicy: "safe",
            payload: { prompt: context.input.input },
          },
        };
      }
      if (context.input.kind === "effect_settlement") {
        toolRequests += 1;
        return {
          kind: "tool_requests",
          state: { phase: "tool" },
          requests: [{
            service: "external-tool",
            operation: "echo",
            replayPolicy: "safe",
            payload: { model: context.input.settlement },
          }],
        };
      }
      if (context.input.kind === "tool_settlements") {
        return {
          kind: "turn_complete",
          state: { phase: "complete" },
          result: { tool: context.input.results[0]?.settlement ?? null },
        };
      }
      throw new Error(`unexpected core input ${context.input.kind}`);
    },
  });
  const identity = {
    sessionId: "session_phase0",
    runtimeRevisionDigest: `sha256:${"a".repeat(64)}` as const,
    adapterAbiVersion: 1,
    checkpointSchemaVersion: 1,
  };
  const registration = (id: string, priority: number): ExtensionRegistration => ({
    manifest: { id, priority, tools: [], patchableFields: {} },
    create: () => ({
      async initialize() { hooks.push(`${id}:initialize`); },
      async beforeAgentStart() { hooks.push(`${id}:beforeAgentStart`); },
      async beforeTurn() { hooks.push(`${id}:beforeTurn`); },
      async beforeModelRequest() { hooks.push(`${id}:beforeModelRequest`); },
      async afterModelResponse() { hooks.push(`${id}:afterModelResponse`); },
      async beforeToolCall() { hooks.push(`${id}:beforeToolCall`); },
      async afterToolCall() { hooks.push(`${id}:afterToolCall`); },
      async afterTurn() { hooks.push(`${id}:afterTurn`); },
    }),
  });
  const engine = new LowLevelPiAgentEngine(identity, coreFactory);
  engine.registerExtension(registration("b", 20));
  engine.registerExtension(registration("a", 10));
  const authority = () => createOpaqueTurnAuthority(new Uint8Array([1, 2, 3]));
  const genesis = await engine.createGenesisCheckpoint({
    turnId: "turn_phase0",
    input: { prompt: "hello" },
    initialCoreState: { phase: "initial" },
  });
  const model = await engine.step({ authority: authority(), checkpoint: genesis });
  if (model.kind !== "effect_request" || model.request.service !== "model") {
    throw new Error("low-level engine did not emit the model boundary");
  }
  const tool = await engine.step({
    authority: authority(),
    checkpoint: model.checkpoint,
    settlement: {
      requestDigest: model.request.requestDigest,
      outcome: { kind: "success", result: { text: "model response" } },
    },
  });
  if (tool.kind !== "effect_request" || tool.request.service === "model") {
    throw new Error("low-level engine did not emit the tool boundary");
  }
  const completed = await engine.step({
    authority: authority(),
    checkpoint: tool.checkpoint,
    settlement: {
      requestDigest: tool.request.requestDigest,
      outcome: { kind: "success", result: { text: "tool response" } },
    },
  });
  return { completed: completed.kind === "turn_complete", modelRequests, toolRequests, hooks };
}

export default {
  async fetch(request: Request, env: { readonly MARKER: string }): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (path === "/identity") {
      return Response.json({ marker: env.MARKER });
    }
    if (path === "/counter") {
      counter += 1;
      return Response.json({ count: counter });
    }
    if (path === "/agent-turn") {
      return Response.json(await runAgentTurn());
    }
    if (path === "/outbound") {
      const fetchDenied = await denied(() =>
        fetch("https://192.0.2.1/", { signal: AbortSignal.timeout(250) })
      );
      const webSocketDenied = await denied(
        () => new Promise<void>((resolve, reject) => {
          const socket = new WebSocket("wss://192.0.2.1/");
          const timeout = setTimeout(() => {
            socket.close();
            reject(new Error("WebSocket did not settle"));
          }, 250);
          socket.addEventListener("open", () => {
            clearTimeout(timeout);
            resolve();
          }, { once: true });
          socket.addEventListener("error", () => {
            clearTimeout(timeout);
            reject(new Error("WebSocket denied"));
          }, { once: true });
        }),
      );
      const rawSocketDenied = await denied(async () => {
        const { connect } = await import("cloudflare:sockets");
        const socket = connect({ hostname: "192.0.2.1", port: 9 });
        await Promise.race([
          socket.opened,
          new Promise<never>((_resolve, reject) =>
            setTimeout(() => reject(new Error("raw socket did not settle")), 250)
          ),
        ]);
        await socket.close();
      });
      return Response.json({ fetchDenied, webSocketDenied, rawSocketDenied });
    }
    return new Response("not found", { status: 404 });
  },
};
