import { randomUUID } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";

import type { PiAgentCoreModelConfiguration } from "@circulusd/pi-runtime";
import type { AssistantMessage, Context, ToolCall } from "@earendil-works/pi-ai";

import {
  ModelProviderError,
  textOfContent,
  type ModelCompletionInput,
  type ModelProvider,
  type ModelProviderDescription,
} from "./types.ts";

export const MOCK_MODEL: PiAgentCoreModelConfiguration = Object.freeze({
  id: "circulusd-test-mock",
  api: "circulusd-test-mock",
  provider: "circulusd-test",
  reasoning: false,
  input: ["text"] as const,
  contextWindow: 32_768,
  maxTokens: 4_096,
});

interface PlannedToolCall {
  readonly name: string;
  readonly arguments: Record<string, unknown>;
}

/**
 * Deterministic scripted model. It never talks to a network: it picks a tool
 * from simple prompt heuristics, and once tool results arrive it writes a
 * final answer. This is enough to drive the real circulusd engine through the
 * full model -> tool -> model -> turn_complete boundary chain.
 */
export class MockModelProvider implements ModelProvider {
  readonly configuration = MOCK_MODEL;
  readonly #deltaDelayMs: number;
  readonly #toolNames: readonly string[];

  constructor(options: { readonly deltaDelayMs?: number; readonly toolNames?: readonly string[] } = {}) {
    this.#deltaDelayMs = options.deltaDelayMs ?? 12;
    this.#toolNames = options.toolNames ?? ["echo", "now", "calculator", "python"];
  }

  describe(): ModelProviderDescription {
    return {
      kind: "mock",
      modelId: MOCK_MODEL.id,
      api: MOCK_MODEL.api,
      provider: MOCK_MODEL.provider,
      baseUrl: null,
      streaming: true,
      apiKeyEnv: null,
      apiKeyPresent: false,
      contextWindow: MOCK_MODEL.contextWindow,
      reasoning: MOCK_MODEL.reasoning,
      supportsTools: true,
    };
  }

  async complete({ context, signal, onDelta }: ModelCompletionInput): Promise<AssistantMessage> {
    const messages = context.messages;
    const last = messages[messages.length - 1];
    const lastUser = [...messages].reverse().find((message) => message.role === "user");
    const prompt = lastUser === undefined ? "" : textOfContent(lastUser.content);
    const inputTokens = estimateTokens(context);

    if (last?.role === "toolResult") {
      const results: string[] = [];
      for (let index = messages.length - 1; index >= 0; index -= 1) {
        const message = messages[index];
        if (message?.role !== "toolResult") break;
        results.unshift(
          `${message.toolName}${message.isError ? " (error)" : ""}: ${textOfContent(message.content)}`,
        );
      }
      const reply = `[mock] 도구 실행 결과입니다.\n${results.join("\n")}`;
      await this.#stream(reply, onDelta, signal);
      return this.#assistant([{ type: "text", text: reply }], "stop", inputTokens);
    }

    // The tools the engine actually offers for this turn come with the context
    // (python is absent when the sandbox could not start); a tool the context
    // lacks is not called, or the result would just be "unknown tool".
    const available = Array.isArray(context.tools) ? context.tools.map((tool) => tool.name) : this.#toolNames;
    const plan = planToolCall(prompt);
    if (plan !== null && available.includes(plan.name)) {
      const toolCall: ToolCall = {
        type: "toolCall",
        id: `call_${randomUUID().slice(0, 8)}`,
        name: plan.name,
        arguments: plan.arguments,
      };
      return this.#assistant([toolCall], "toolUse", inputTokens);
    }

    const toolNames = available.join(", ");
    const examples = ['"12*(3+4) 계산해줘"', '"지금 몇 시야?"', '"echo 안녕"', ...(available.includes("python") ? ['"python: print(2**10)"'] : [])];
    const unavailable = plan === null ? "" : `\`${plan.name}\` 도구는 이 백엔드에서 꺼져 있어 호출하지 않았습니다(기동 로그와 /v1/capabilities 의 execution 참고). `;
    const reply =
      `[mock] "${prompt}" 을(를) 받았습니다. 이 답변은 실제 LLM이 아니라 circulusd-test 내장 모의 모델이 만든 것입니다. ${unavailable}` +
      `사용 가능한 도구: ${toolNames}. 예: ${examples.join(", ")}.`;
    await this.#stream(reply, onDelta, signal);
    return this.#assistant([{ type: "text", text: reply }], "stop", inputTokens);
  }

  async #stream(text: string, onDelta: (text: string) => void, signal: AbortSignal): Promise<void> {
    for (let offset = 0; offset < text.length; offset += 6) {
      if (signal.aborted) {
        throw new ModelProviderError("MODEL_ABORTED", "mock model stream aborted");
      }
      onDelta(text.slice(offset, offset + 6));
      if (this.#deltaDelayMs > 0) await sleep(this.#deltaDelayMs);
    }
  }

  #assistant(
    content: AssistantMessage["content"],
    stopReason: "stop" | "toolUse",
    inputTokens: number,
  ): AssistantMessage {
    const outputTokens = Math.max(1, Math.ceil(JSON.stringify(content).length / 4));
    return {
      role: "assistant",
      content,
      api: MOCK_MODEL.api,
      provider: MOCK_MODEL.provider,
      model: MOCK_MODEL.id,
      usage: {
        input: inputTokens,
        output: outputTokens,
        cacheRead: 0,
        cacheWrite: 0,
        totalTokens: inputTokens + outputTokens,
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
      },
      stopReason,
      timestamp: Date.now(),
    };
  }
}

export function planToolCall(prompt: string): PlannedToolCall | null {
  const echo = /^\s*(?:echo|따라\s*해|따라해)\s*[:：]?\s*(.+)$/i.exec(prompt);
  if (echo?.[1] !== undefined) {
    return { name: "echo", arguments: { text: echo[1].trim() } };
  }
  const fenced = /```(?:python|py)?[ \t]*\r?\n([\s\S]*?)```/i.exec(prompt);
  if (fenced?.[1] !== undefined && fenced[1].trim() !== "") {
    return { name: "python", arguments: { code: fenced[1] } };
  }
  const inline = /^\s*(?:python|파이썬)\s*[:：]\s*([\s\S]+)$/i.exec(prompt);
  if (inline?.[1] !== undefined && inline[1].trim() !== "") {
    return { name: "python", arguments: { code: inline[1].trim() } };
  }
  const expression = /[\d(][\d\s+\-*/%^().]*[\d)]/.exec(prompt);
  if (expression !== null && /\d\s*[+\-*/%^]\s*[\d(]/.test(expression[0])) {
    return { name: "calculator", arguments: { expression: expression[0].trim() } };
  }
  if (
    /(지금|현재)\s*(몇\s*시|시간|시각|날짜)|몇\s*시|what time|current time|today'?s date|\bdate\b|\btime\b/i.test(
      prompt,
    )
  ) {
    return { name: "now", arguments: {} };
  }
  return null;
}

function estimateTokens(context: Context): number {
  const size = JSON.stringify(context).length;
  return Math.max(1, Math.ceil(size / 4));
}
