// Standalone check that a local Ollama model works through the pinned pi-ai
// openai-completions API with tool calling, independent of the circulusd engine.
//   node scripts/ollama-probe.mjs [model] [base-url]
import { stream } from "@earendil-works/pi-ai/compat";

const modelId = process.argv[2] ?? "qwen3:8b";
const baseUrl = process.argv[3] ?? "http://127.0.0.1:11434/v1";
const model = {
  id: modelId,
  name: modelId,
  api: "openai-completions",
  provider: "ollama",
  baseUrl,
  reasoning: true,
  input: ["text"],
  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
  contextWindow: 32_768,
  maxTokens: 8_192,
};
const tools = [
  {
    name: "calculator",
    description: "Evaluate an arithmetic expression and return the number.",
    parameters: {
      type: "object",
      properties: { expression: { type: "string" } },
      required: ["expression"],
      additionalProperties: false,
    },
  },
];

async function run(label, messages) {
  const started = Date.now();
  const events = stream(
    model,
    { systemPrompt: "You are a test agent. Use the calculator tool for arithmetic.", messages, tools },
    { maxTokens: 1024, apiKey: "ollama" },
  );
  const seen = {};
  for await (const event of events) seen[event.type] = (seen[event.type] ?? 0) + 1;
  const message = await events.result();
  console.log(`== ${label} (${Date.now() - started}ms) events=${JSON.stringify(seen)}`);
  console.log(
    JSON.stringify(
      {
        stopReason: message.stopReason,
        errorMessage: message.errorMessage,
        usage: message.usage,
        content: message.content.map((block) =>
          block.type === "thinking"
            ? { type: "thinking", chars: block.thinking?.length, head: block.thinking?.slice(0, 80) }
            : block,
        ),
      },
      null,
      1,
    ),
  );
  return message;
}

const prompt = { role: "user", content: "12*(3+4)를 계산해줘", timestamp: Date.now() };
const first = await run("turn 1: expect a tool call", [prompt]);
const call = first.content.find((block) => block.type === "toolCall");
if (call) {
  await run("turn 2: after the tool result", [
    prompt,
    first,
    {
      role: "toolResult",
      toolCallId: call.id,
      toolName: call.name,
      content: [{ type: "text", text: "84" }],
      isError: false,
      timestamp: Date.now(),
    },
  ]);
}
