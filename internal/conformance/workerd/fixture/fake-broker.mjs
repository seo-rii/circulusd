const maximumRequestBytes = 1 << 20;
const modelIdentity = Object.freeze({
  id: "phase0-stable-broker-model",
  api: "circulusd-model-gateway",
  provider: "circulusd",
});
const usage = Object.freeze({
  input: 1,
  output: 1,
  cacheRead: 0,
  cacheWrite: 0,
  totalTokens: 2,
  cost: Object.freeze({
    encoding: "pi-cost-decimal-v1",
    input: "0.000001", output: "0.000002", cacheRead: "0", cacheWrite: "0", total: "0.000003",
  }),
});
const initialModelIdentities = new Set();

async function readBrokerRequest(request, expectedService) {
  if (request.method !== "POST" || request.headers.get("content-type") !== "application/json") {
    throw new Error("fake broker requires canonical JSON POST requests");
  }
  const source = await request.text();
  if (source.length === 0 || source.length > maximumRequestBytes) {
    throw new Error("fake broker request is outside its size bound");
  }
  const body = JSON.parse(source);
  if (
    body === null ||
    typeof body !== "object" ||
    Array.isArray(body) ||
    (body.identity !== "identity-a" && body.identity !== "identity-b") ||
    body.request === null ||
    typeof body.request !== "object" ||
    Array.isArray(body.request) ||
    body.request.service !== expectedService ||
    typeof body.request.requestDigest !== "string" ||
    !/^sha256:[0-9a-f]{64}$/.test(body.request.requestDigest) ||
    body.request.payload === null ||
    typeof body.request.payload !== "object" ||
    Array.isArray(body.request.payload)
  ) {
    throw new Error("fake broker request identity or durable effect is invalid");
  }
  return body;
}

export const model = {
  async fetch(request) {
    try {
      const body = await readBrokerRequest(request, "model");
      const effect = body.request;
      const payload = effect.payload;
      if (
        effect.operation !== "complete" ||
        effect.replayPolicy !== "never" ||
        payload.protocol !== "pi-agent-core" ||
        payload.version !== 2 ||
        payload.packageVersion !== "0.84.3" ||
        payload.model?.id !== modelIdentity.id ||
        payload.model?.api !== modelIdentity.api ||
        payload.model?.provider !== modelIdentity.provider ||
        !Array.isArray(payload.context?.messages) ||
        payload.context.messages.length === 0 ||
        payload.context.messages[0]?.role !== "user" ||
        payload.context.messages[0]?.content !== body.identity
      ) {
        throw new Error("fake model received a non-canonical Pi request");
      }
      const messages = payload.context.messages;
      const last = messages.at(-1);
      const timestampBase = body.identity === "identity-a" ? 1_700_000_001_000 : 1_700_000_002_000;
      if (last.role === "user" && messages.length === 1) {
        initialModelIdentities.add(body.identity);
        if (initialModelIdentities.size < 2) {
          return Response.json({
            requestDigest: effect.requestDigest,
            stage: "rendezvous-pending",
          }, { status: 202 });
        }
        return Response.json({
          requestDigest: effect.requestDigest,
          stage: "model-tool",
          settlement: {
            version: 2,
            message: {
              role: "assistant",
              content: [{
                type: "toolCall",
                id: `call_${body.identity}`,
                name: "echo",
                arguments: { text: body.identity },
              }],
              api: modelIdentity.api,
              provider: modelIdentity.provider,
              model: modelIdentity.id,
              usage,
              stopReason: "toolUse",
              timestamp: timestampBase,
            },
          },
        });
      }
      if (
        last.role !== "toolResult" ||
        last.toolCallId !== `call_${body.identity}` ||
        last.toolName !== "echo" ||
        last.isError !== false ||
        !Array.isArray(last.content) ||
        last.content.length !== 1 ||
        last.content[0]?.type !== "text" ||
        last.content[0]?.text !== body.identity
      ) {
        throw new Error("fake model continuation is not correlated to its tool result");
      }
      return Response.json({
        requestDigest: effect.requestDigest,
        stage: "model-complete",
        settlement: {
          version: 2,
          message: {
            role: "assistant",
            content: [{ type: "text", text: `complete:${body.identity}` }],
            api: modelIdentity.api,
            provider: modelIdentity.provider,
            model: modelIdentity.id,
            usage,
            stopReason: "stop",
            timestamp: timestampBase + 2,
          },
        },
      });
    } catch (error) {
      return Response.json(
        { error: error instanceof Error ? error.message : "invalid fake model request" },
        { status: 400 },
      );
    }
  },
};

export const mcp = {
  async fetch(request) {
    try {
      const body = await readBrokerRequest(request, "external-tool");
      const effect = body.request;
      const toolCall = effect.payload?.toolCall;
      if (
        effect.operation !== "call" ||
        effect.replayPolicy !== "safe" ||
        effect.payload?.protocol !== "pi-agent-core" ||
        effect.payload?.version !== 1 ||
        toolCall?.type !== "toolCall" ||
        toolCall.id !== `call_${body.identity}` ||
        toolCall.name !== "echo" ||
        toolCall.arguments?.text !== body.identity
      ) {
        throw new Error("fake MCP received an uncorrelated Pi tool request");
      }
      const timestampBase = body.identity === "identity-a" ? 1_700_000_001_000 : 1_700_000_002_000;
      return Response.json({
        requestDigest: effect.requestDigest,
        stage: "mcp-echo",
        settlement: {
          version: 1,
          toolCallId: toolCall.id,
          toolName: toolCall.name,
          content: [{ type: "text", text: body.identity }],
          details: { identity: body.identity },
          isError: false,
          timestamp: timestampBase + 1,
        },
      });
    } catch (error) {
      return Response.json(
        { error: error instanceof Error ? error.message : "invalid fake MCP request" },
        { status: 400 },
      );
    }
  },
};
