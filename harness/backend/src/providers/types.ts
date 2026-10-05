import type { PiAgentCoreModelConfiguration } from "@circulusd/pi-runtime";
import type { AssistantMessage, Context, ToolCall } from "@earendil-works/pi-ai";

export type ModelProviderKind = "mock" | "ollama" | "anthropic" | "openai-compatible";

export interface ModelProviderDescription {
  readonly kind: ModelProviderKind;
  readonly modelId: string;
  readonly api: string;
  readonly provider: string;
  readonly baseUrl: string | null;
  readonly streaming: boolean;
  readonly apiKeyEnv: string | null;
  readonly apiKeyPresent: boolean;
  readonly contextWindow: number;
  readonly reasoning: boolean;
  readonly supportsTools: boolean;
}

export interface ModelCompletionInput {
  readonly context: Context;
  readonly signal: AbortSignal;
  readonly onDelta: (text: string) => void;
  /** Reasoning/thinking text from models that expose it (never part of the durable transcript). */
  readonly onThinking?: (text: string) => void;
}

/**
 * The test harness' stand-in for circulusd's model gateway: it receives the
 * Pi context captured by the circulusd adapter and must return one Pi
 * AssistantMessage that the adapter will accept as the model settlement.
 */
export interface ModelProvider {
  readonly configuration: PiAgentCoreModelConfiguration;
  describe(): ModelProviderDescription;
  complete(input: ModelCompletionInput): Promise<AssistantMessage>;
}

export class ModelProviderError extends Error {
  readonly code: string;
  constructor(code: string, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "ModelProviderError";
    this.code = code;
  }
}

export function textOfContent(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .filter(
      (block): block is { readonly type: "text"; readonly text: string } =>
        block !== null &&
        typeof block === "object" &&
        (block as { type?: unknown }).type === "text" &&
        typeof (block as { text?: unknown }).text === "string",
    )
    .map((block) => block.text)
    .join("");
}

export function toolCallsOf(content: unknown): readonly ToolCall[] {
  if (!Array.isArray(content)) return [];
  return content.filter(
    (block): block is ToolCall =>
      block !== null && typeof block === "object" && (block as { type?: unknown }).type === "toolCall",
  );
}

/**
 * Reduce a provider AssistantMessage to exactly the fields the circulusd Pi
 * adapter accepts (see pi-cost-codec `assistantRecords`): provider diagnostics,
 * deferred handles and thinking blocks are dropped, and the model identity is
 * pinned to the immutable runtime configuration.
 */
export function sanitizeAssistantMessage(
  message: AssistantMessage,
  configuration: PiAgentCoreModelConfiguration,
): AssistantMessage {
  const content = message.content
    .filter((block) => block.type === "text" || block.type === "toolCall")
    .map((block) =>
      block.type === "text"
        ? { type: "text" as const, text: block.text }
        : { type: "toolCall" as const, id: block.id, name: block.name, arguments: block.arguments },
    );
  const cost = message.usage.cost;
  const sanitized: AssistantMessage = {
    role: "assistant",
    content,
    api: configuration.api,
    provider: configuration.provider,
    model: configuration.id,
    usage: {
      input: nonNegativeInteger(message.usage.input),
      output: nonNegativeInteger(message.usage.output),
      cacheRead: nonNegativeInteger(message.usage.cacheRead),
      cacheWrite: nonNegativeInteger(message.usage.cacheWrite),
      totalTokens: nonNegativeInteger(message.usage.totalTokens),
      cost: {
        input: nonNegativeNumber(cost?.input),
        output: nonNegativeNumber(cost?.output),
        cacheRead: nonNegativeNumber(cost?.cacheRead),
        cacheWrite: nonNegativeNumber(cost?.cacheWrite),
        total: nonNegativeNumber(cost?.total),
      },
    },
    stopReason: message.stopReason,
    timestamp: Number.isSafeInteger(message.timestamp) ? message.timestamp : Date.now(),
  };
  if (typeof message.responseModel === "string") sanitized.responseModel = message.responseModel;
  if (typeof message.responseId === "string") sanitized.responseId = message.responseId;
  if (typeof message.rawStopReason === "string") sanitized.rawStopReason = message.rawStopReason;
  if (typeof message.errorMessage === "string") sanitized.errorMessage = message.errorMessage;
  if (typeof message.endTurn === "boolean") sanitized.endTurn = message.endTurn;
  return sanitized;
}

function nonNegativeInteger(value: unknown): number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

function nonNegativeNumber(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? value : 0;
}
