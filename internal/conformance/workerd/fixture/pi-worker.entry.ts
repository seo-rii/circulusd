import {
  LowLevelPiAgentEngine,
  createOpaqueTurnAuthority,
  createPiAgentCoreFactory,
  createPiAgentCoreInitialState,
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
  readonly modelBoundaries: number;
  readonly toolRequests: number;
  readonly trace: readonly string[];
  readonly hooks: readonly string[];
}> {
  const hooks: string[] = [];
  const model = {
    id: "phase0-deterministic-model",
    api: "circulusd-model-gateway",
    provider: "circulusd",
    reasoning: false,
    input: ["text"],
    contextWindow: 4_096,
    maxTokens: 512,
  } as const;
  const coreFactory = createPiAgentCoreFactory({
    systemPrompt: "You are the deterministic Phase 0A conformance agent.",
    model,
    tools: [{
      name: "echo",
      description: "Echo one text value",
      parameters: {
        type: "object",
        properties: { text: { type: "string" } },
        required: ["text"],
        additionalProperties: false,
      },
      replayPolicy: "safe",
    }],
  });
  const identity = {
    sessionId: "session_phase0",
    runtimeRevisionDigest: `sha256:${"a".repeat(64)}` as const,
    adapterAbiVersion: 2,
    checkpointSchemaVersion: 2,
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
  const engines: LowLevelPiAgentEngine[] = [];
  for (let index = 0; index < 4; index += 1) {
    const engine = new LowLevelPiAgentEngine(identity, coreFactory);
    engine.registerExtension(registration("b", 20));
    engine.registerExtension(registration("a", 10));
    engines.push(engine);
  }
  const authority = () => createOpaqueTurnAuthority(new Uint8Array([1, 2, 3]));
  const genesis = await engines[0]!.createGenesisCheckpoint({
    turnId: "turn_phase0",
    input: { prompt: "hello", timestamp: 1_700_000_000_000 },
    initialCoreState: createPiAgentCoreInitialState(),
  });
  const firstModel = await engines[0]!.step({ authority: authority(), checkpoint: genesis });
  if (
    firstModel.kind !== "effect_request" ||
    firstModel.request.service !== "model" ||
    firstModel.checkpoint.adapterAbiVersion !== 2 ||
    firstModel.checkpoint.checkpointSchemaVersion !== 2
  ) {
    throw new Error("pinned Pi adapter did not emit its first model boundary");
  }
  const tool = await engines[1]!.step({
    authority: authority(),
    checkpoint: firstModel.checkpoint,
    settlement: {
      requestDigest: firstModel.request.requestDigest,
      outcome: {
        kind: "success",
        result: {
          version: 1,
          message: {
            role: "assistant",
            content: [{
              type: "toolCall",
              id: "phase0_echo_1",
              name: "echo",
              arguments: { text: "hello" },
            }],
            api: model.api,
            provider: model.provider,
            model: model.id,
            usage: {
              input: 1,
              output: 1,
              cacheRead: 0,
              cacheWrite: 0,
              totalTokens: 2,
              cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
            },
            stopReason: "toolUse",
            timestamp: 1_700_000_000_001,
          },
        },
      },
    },
  });
  if (tool.kind !== "effect_request" || tool.request.service === "model") {
    throw new Error("pinned Pi adapter did not emit the tool boundary");
  }
  const secondModel = await engines[2]!.step({
    authority: authority(),
    checkpoint: tool.checkpoint,
    settlement: {
      requestDigest: tool.request.requestDigest,
      outcome: {
        kind: "success",
        result: {
          version: 1,
          toolCallId: "phase0_echo_1",
          toolName: "echo",
          content: [{ type: "text", text: "hello" }],
          isError: false,
          timestamp: 1_700_000_000_002,
        },
      },
    },
  });
  if (secondModel.kind !== "effect_request" || secondModel.request.service !== "model") {
    throw new Error("pinned Pi adapter did not resume with its second model boundary");
  }
  const completed = await engines[3]!.step({
    authority: authority(),
    checkpoint: secondModel.checkpoint,
    settlement: {
      requestDigest: secondModel.request.requestDigest,
      outcome: {
        kind: "success",
        result: {
          version: 1,
          message: {
            role: "assistant",
            content: [{ type: "text", text: "done" }],
            api: model.api,
            provider: model.provider,
            model: model.id,
            usage: {
              input: 2,
              output: 1,
              cacheRead: 0,
              cacheWrite: 0,
              totalTokens: 3,
              cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
            },
            stopReason: "stop",
            timestamp: 1_700_000_000_003,
          },
        },
      },
    },
  });
  const trace = [firstModel.request.service, tool.request.service, secondModel.request.service,
    completed.kind] as const;
  return {
    completed: completed.kind === "turn_complete",
    modelBoundaries: trace.filter((entry) => entry === "model").length,
    toolRequests: trace.filter((entry) => entry === "external-tool").length,
    trace,
    hooks,
  };
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
