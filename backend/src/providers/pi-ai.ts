import { getModel, getModels, stream } from "@earendil-works/pi-ai/compat";
import type { Api, AssistantMessage, Context, Model } from "@earendil-works/pi-ai";
import type { PiAgentCoreModelConfiguration } from "@circulusd/pi-runtime";

import {
  ModelProviderError,
  sanitizeAssistantMessage,
  type ModelCompletionInput,
  type ModelProvider,
  type ModelProviderDescription,
  type ModelProviderKind,
} from "./types.ts";

export interface PiAiProviderOptions {
  readonly kind: Exclude<ModelProviderKind, "mock">;
  readonly modelId: string;
  /** Required for every kind except `anthropic` (which uses pi-ai's catalog). */
  readonly baseUrl?: string;
  /** pi-ai provider id used for OpenAI-compatible servers (e.g. "openai", "ollama"). */
  readonly providerId?: string;
  readonly apiKeyEnv: string;
  readonly apiKeyRequired: boolean;
  /** Sent when the env var is unset and the server ignores the key (Ollama). */
  readonly placeholderApiKey?: string;
  readonly contextWindow?: number;
  readonly maxOutputTokens?: number;
  readonly reasoning?: boolean;
  /** When false, tool definitions are withheld from the request (the server would reject them). */
  readonly supportsTools?: boolean;
}

const DEFAULT_MAX_OUTPUT_TOKENS = 4_096;

/**
 * Real model provider backed by the same pinned pi-ai 0.84.3 that
 * circulusd's Pi adapter is built against. Streams text (and thinking)
 * deltas to the caller and returns the final sanitized AssistantMessage.
 */
export class PiAiModelProvider implements ModelProvider {
  readonly configuration: PiAgentCoreModelConfiguration;
  readonly #model: Model<Api>;
  readonly #options: PiAiProviderOptions;

  constructor(options: PiAiProviderOptions) {
    this.#options = options;
    if (options.kind === "anthropic") {
      const model = getModel("anthropic", options.modelId as never) as Model<Api> | undefined;
      if (model === undefined) {
        const known = getModels("anthropic")
          .map((entry) => entry.id)
          .join(", ");
        throw new ModelProviderError(
          "UNKNOWN_MODEL",
          `unknown anthropic model id "${options.modelId}"; known ids: ${known}`,
        );
      }
      this.#model = model;
    } else {
      if (options.baseUrl === undefined) {
        throw new ModelProviderError("INVALID_CONFIGURATION", `${options.kind} requires a base URL`);
      }
      const contextWindow = options.contextWindow ?? 128_000;
      this.#model = {
        id: options.modelId,
        name: options.modelId,
        api: "openai-completions",
        provider: options.providerId ?? "openai",
        baseUrl: options.baseUrl,
        reasoning: options.reasoning ?? false,
        input: ["text"],
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
        contextWindow,
        maxTokens: Math.min(8_192, contextWindow),
      };
    }
    this.configuration = Object.freeze({
      id: this.#model.id,
      api: this.#model.api,
      provider: this.#model.provider,
      reasoning: this.#model.reasoning,
      input: [...this.#model.input],
      contextWindow: this.#model.contextWindow,
      maxTokens: Math.min(this.#model.maxTokens, this.#model.contextWindow),
    });
  }

  describe(): ModelProviderDescription {
    return {
      kind: this.#options.kind,
      modelId: this.configuration.id,
      api: this.configuration.api,
      provider: this.configuration.provider,
      baseUrl: this.#model.baseUrl,
      streaming: true,
      apiKeyEnv: this.#options.apiKeyEnv,
      apiKeyPresent: Boolean(process.env[this.#options.apiKeyEnv]),
      contextWindow: this.configuration.contextWindow,
      reasoning: this.configuration.reasoning,
      supportsTools: this.#options.supportsTools ?? true,
    };
  }

  async complete({ context, signal, onDelta, onThinking }: ModelCompletionInput): Promise<AssistantMessage> {
    const apiKey = process.env[this.#options.apiKeyEnv] ?? this.#options.placeholderApiKey;
    if (this.#options.apiKeyRequired && !apiKey) {
      throw new ModelProviderError(
        "API_KEY_MISSING",
        `${this.#options.apiKeyEnv} is not set; export it before starting the backend or use CIRCULUSD_TEST_MODEL=mock`,
      );
    }
    let requestContext: Context = context;
    if (this.#options.supportsTools === false && context.tools !== undefined) {
      const { tools: _withheld, ...withoutTools } = context;
      requestContext = withoutTools;
    }
    const events = stream(this.#model, requestContext, {
      ...(apiKey ? { apiKey } : {}),
      signal,
      maxTokens: Math.min(
        this.configuration.maxTokens,
        this.#options.maxOutputTokens ?? DEFAULT_MAX_OUTPUT_TOKENS,
      ),
    });
    for await (const event of events) {
      if (event.type === "text_delta") onDelta(event.delta);
      else if (event.type === "thinking_delta") onThinking?.(event.delta);
    }
    const message = await events.result();
    if (message.stopReason === "error") {
      throw new ModelProviderError(
        "MODEL_REQUEST_FAILED",
        message.errorMessage ?? "model request failed",
      );
    }
    if (message.stopReason === "aborted") {
      throw new ModelProviderError("MODEL_ABORTED", "model request aborted");
    }
    return sanitizeAssistantMessage(message, this.configuration);
  }
}
