import {
  LowLevelPiAgentEngine,
  createOpaqueTurnAuthority,
  createPiAgentCoreFactory,
  createPiAgentCoreInitialState,
  encodePiAgentCoreModelSettlement,
  type ExtensionRegistration,
} from "../../../../workers/pi-runtime/src/index.ts";
import type { NormalizedValue } from "../../../../packages/protocol-types/src/index.ts";

let counter = 0;

interface FetcherBinding {
  fetch(input: Request | string, init?: RequestInit): Promise<Response>;
}

interface WorkerEnvironment {
  readonly MARKER: string;
  readonly MODEL?: FetcherBinding;
  readonly MCP?: FetcherBinding;
}

interface BrokerEnvelope {
  readonly requestDigest: string;
  readonly stage: string;
  readonly settlement?: NormalizedValue;
}

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
        result: encodePiAgentCoreModelSettlement({
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
            cost: { input: 0.000001, output: 0.000002, cacheRead: 0, cacheWrite: 0, total: 0.000003 },
          },
          stopReason: "toolUse",
          timestamp: 1_700_000_000_001,
        }),
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
        result: encodePiAgentCoreModelSettlement({
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
            cost: { input: 0.000002, output: 0.000002, cacheRead: 0, cacheWrite: 0, total: 0.000004 },
          },
          stopReason: "stop",
          timestamp: 1_700_000_000_003,
        }),
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

async function runStableBrokerTurn(env: WorkerEnvironment): Promise<{
  readonly identity: string;
  readonly completed: boolean;
  readonly trace: readonly string[];
  readonly brokerTrace: readonly string[];
  readonly initialModelAttempts: number;
}> {
  if (
    env.MODEL === undefined ||
    typeof env.MODEL.fetch !== "function" ||
    env.MCP === undefined ||
    typeof env.MCP.fetch !== "function"
  ) {
    throw new Error("stable broker bindings are missing");
  }
  if (env.MARKER !== "identity-a" && env.MARKER !== "identity-b") {
    throw new Error("stable broker identity is invalid");
  }
  const identity = env.MARKER;
  const model = {
    id: "phase0-stable-broker-model",
    api: "circulusd-model-gateway",
    provider: "circulusd",
    reasoning: false,
    input: ["text"],
    contextWindow: 4_096,
    maxTokens: 512,
  } as const;
  const coreFactory = createPiAgentCoreFactory({
    systemPrompt: "Use the stable Phase 0A mock broker bindings.",
    model,
    tools: [{
      name: "echo",
      description: "Echo one identity",
      parameters: {
        type: "object",
        properties: { text: { type: "string", enum: [identity] } },
        required: ["text"],
        additionalProperties: false,
      },
      replayPolicy: "safe",
    }],
  });
  const engineIdentity = {
    sessionId: `session_phase0_${identity.replace("-", "_")}`,
    runtimeRevisionDigest: `sha256:${"b".repeat(64)}` as const,
    adapterAbiVersion: 2,
    checkpointSchemaVersion: 2,
  };
  const engines = Array.from(
    { length: 4 },
    () => new LowLevelPiAgentEngine(engineIdentity, coreFactory),
  );
  const timestampBase = identity === "identity-a" ? 1_700_000_001_000 : 1_700_000_002_000;
  const genesis = await engines[0]!.createGenesisCheckpoint({
    turnId: `turn_phase0_${identity.replace("-", "_")}`,
    input: { prompt: identity, timestamp: timestampBase - 1 },
    initialCoreState: createPiAgentCoreInitialState(),
  });
  const firstModel = await engines[0]!.step({
    authority: createOpaqueTurnAuthority(new Uint8Array([4, 5, 6])),
    checkpoint: genesis,
  });
  if (firstModel.kind !== "effect_request" || firstModel.request.service !== "model") {
    throw new Error("stable broker turn did not emit its first model request");
  }
  let firstModelResponse: Response | undefined;
  let firstModelEnvelope: BrokerEnvelope | undefined;
  let initialModelAttempts = 0;
  while (initialModelAttempts < 8) {
    initialModelAttempts += 1;
    const response = await env.MODEL.fetch("https://model.phase0.invalid/complete", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identity, request: firstModel.request }),
    });
    const envelope = await response.json() as BrokerEnvelope;
    if (response.status === 202) {
      if (
        envelope.requestDigest !== firstModel.request.requestDigest ||
        envelope.stage !== "rendezvous-pending" ||
        envelope.settlement !== undefined
      ) {
        throw new Error("stable model binding returned an invalid rendezvous response");
      }
      continue;
    }
    firstModelResponse = response;
    firstModelEnvelope = envelope;
    break;
  }
  if (
    firstModelResponse === undefined ||
    firstModelEnvelope === undefined ||
    !firstModelResponse.ok ||
    firstModelEnvelope.requestDigest !== firstModel.request.requestDigest ||
    firstModelEnvelope.stage !== "model-tool" ||
    firstModelEnvelope.settlement === null ||
    typeof firstModelEnvelope.settlement !== "object"
  ) {
    throw new Error("stable model binding returned an uncorrelated first settlement");
  }
  const tool = await engines[1]!.step({
    authority: createOpaqueTurnAuthority(new Uint8Array([4, 5, 6])),
    checkpoint: firstModel.checkpoint,
    settlement: {
      requestDigest: firstModel.request.requestDigest,
      outcome: { kind: "success", result: firstModelEnvelope.settlement },
    },
  });
  if (tool.kind !== "effect_request" || tool.request.service !== "external-tool") {
    throw new Error("stable broker turn did not emit its MCP tool request");
  }
  const toolResponse = await env.MCP.fetch("https://mcp.phase0.invalid/call", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ identity, request: tool.request }),
  });
  const toolEnvelope = await toolResponse.json() as BrokerEnvelope;
  if (
    !toolResponse.ok ||
    toolEnvelope.requestDigest !== tool.request.requestDigest ||
    toolEnvelope.stage !== "mcp-echo" ||
    toolEnvelope.settlement === null ||
    typeof toolEnvelope.settlement !== "object"
  ) {
    throw new Error("stable MCP binding returned an uncorrelated tool settlement");
  }
  const secondModel = await engines[2]!.step({
    authority: createOpaqueTurnAuthority(new Uint8Array([4, 5, 6])),
    checkpoint: tool.checkpoint,
    settlement: {
      requestDigest: tool.request.requestDigest,
      outcome: { kind: "success", result: toolEnvelope.settlement },
    },
  });
  if (secondModel.kind !== "effect_request" || secondModel.request.service !== "model") {
    throw new Error("stable broker turn did not emit its continuation model request");
  }
  const secondModelResponse = await env.MODEL.fetch("https://model.phase0.invalid/complete", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ identity, request: secondModel.request }),
  });
  const secondModelEnvelope = await secondModelResponse.json() as BrokerEnvelope;
  if (
    !secondModelResponse.ok ||
    secondModelEnvelope.requestDigest !== secondModel.request.requestDigest ||
    secondModelEnvelope.stage !== "model-complete" ||
    secondModelEnvelope.settlement === null ||
    typeof secondModelEnvelope.settlement !== "object"
  ) {
    throw new Error("stable model binding returned an uncorrelated final settlement");
  }
  const completed = await engines[3]!.step({
    authority: createOpaqueTurnAuthority(new Uint8Array([4, 5, 6])),
    checkpoint: secondModel.checkpoint,
    settlement: {
      requestDigest: secondModel.request.requestDigest,
      outcome: { kind: "success", result: secondModelEnvelope.settlement },
    },
  });
  return {
    identity,
    completed: completed.kind === "turn_complete",
    initialModelAttempts,
    trace: [
      firstModel.request.service,
      tool.request.service,
      secondModel.request.service,
      completed.kind,
    ],
    brokerTrace: [firstModelEnvelope.stage, toolEnvelope.stage, secondModelEnvelope.stage],
  };
}

export default {
  async fetch(request: Request, env: WorkerEnvironment): Promise<Response> {
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
    if (path === "/stable-broker-turn") {
      if (
        env.MODEL === undefined ||
        typeof env.MODEL.fetch !== "function" ||
        env.MCP === undefined ||
        typeof env.MCP.fetch !== "function"
      ) {
        return Response.json({ code: "missing_binding" }, { status: 503 });
      }
      return Response.json(await runStableBrokerTurn(env));
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
