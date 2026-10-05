import { MockModelProvider } from "./mock.ts";
import { PiAiModelProvider } from "./pi-ai.ts";
import { ModelProviderError, type ModelProvider } from "./types.ts";

export { MOCK_MODEL, MockModelProvider, planToolCall } from "./mock.ts";
export { PiAiModelProvider } from "./pi-ai.ts";
export * from "./types.ts";

export const DEFAULT_OLLAMA_BASE_URL = "http://127.0.0.1:11434/v1";

export interface ResolveModelProviderOptions {
  /** Injectable for tests; defaults to the global fetch. */
  readonly fetch?: typeof fetch;
  readonly log?: (line: string) => void;
  /** Passed to every real provider (see PiAiProviderOptions.stallTimeoutMs). */
  readonly stallTimeoutMs?: number;
}

/**
 * CIRCULUSD_TEST_MODEL grammar:
 *   mock
 *   ollama:<model>[@<base-url>]                 base URL defaults to OLLAMA_HOST or http://127.0.0.1:11434/v1
 *   anthropic:<model-id>
 *   openai-compatible:<model-id>@<base-url>
 */
export async function resolveModelProvider(
  spec: string | undefined,
  options: ResolveModelProviderOptions = {},
): Promise<ModelProvider> {
  const trimmed = (spec ?? "mock").trim();
  if (trimmed === "" || trimmed === "mock") {
    return new MockModelProvider();
  }
  const separator = trimmed.indexOf(":");
  const kind = separator === -1 ? trimmed : trimmed.slice(0, separator);
  const rest = separator === -1 ? "" : trimmed.slice(separator + 1);
  const stall = options.stallTimeoutMs === undefined ? {} : { stallTimeoutMs: options.stallTimeoutMs };

  if (kind === "ollama") {
    const at = rest.indexOf("@");
    const modelId = at === -1 ? rest : rest.slice(0, at);
    const baseUrl = at === -1 ? defaultOllamaBaseUrl(process.env.OLLAMA_HOST) : rest.slice(at + 1);
    if (modelId === "" || baseUrl === "") {
      throw new ModelProviderError("INVALID_CONFIGURATION", "ollama:<model>[@<base-url>] is required");
    }
    const metadata = await describeOllamaModel(modelId, baseUrl, options.fetch ?? fetch);
    if (!metadata.tools) {
      options.log?.(
        `warning: Ollama model ${metadata.name} does not advertise the "tools" capability; tool definitions will be withheld`,
      );
    }
    return new PiAiModelProvider({
      kind: "ollama",
      modelId: metadata.name,
      baseUrl,
      providerId: "ollama",
      apiKeyEnv: "OLLAMA_API_KEY",
      apiKeyRequired: false,
      placeholderApiKey: "ollama",
      contextWindow: metadata.contextLength,
      reasoning: metadata.thinking,
      supportsTools: metadata.tools,
      ...stall,
    });
  }
  if (kind === "anthropic") {
    if (rest === "") {
      throw new ModelProviderError("INVALID_CONFIGURATION", "anthropic:<model-id> is required");
    }
    return new PiAiModelProvider({
      kind: "anthropic",
      modelId: rest,
      apiKeyEnv: "ANTHROPIC_API_KEY",
      apiKeyRequired: true,
      ...stall,
    });
  }
  if (kind === "openai-compatible") {
    const at = rest.indexOf("@");
    if (at <= 0 || at === rest.length - 1) {
      throw new ModelProviderError(
        "INVALID_CONFIGURATION",
        "openai-compatible:<model-id>@<base-url> is required",
      );
    }
    return new PiAiModelProvider({
      kind: "openai-compatible",
      modelId: rest.slice(0, at),
      baseUrl: rest.slice(at + 1),
      apiKeyEnv: "OPENAI_API_KEY",
      apiKeyRequired: false,
      placeholderApiKey: "none",
      ...stall,
    });
  }
  throw new ModelProviderError(
    "INVALID_CONFIGURATION",
    `unsupported CIRCULUSD_TEST_MODEL "${trimmed}" (expected mock | ollama:<model> | anthropic:<id> | openai-compatible:<id>@<url>)`,
  );
}

/** Accepts Ollama's own OLLAMA_HOST forms: "host:port", "http://host:port", with or without "/v1". */
export function defaultOllamaBaseUrl(ollamaHost: string | undefined): string {
  const raw = ollamaHost?.trim() ?? "";
  if (raw === "") return DEFAULT_OLLAMA_BASE_URL;
  const withScheme = /^https?:\/\//i.test(raw) ? raw : `http://${raw}`;
  const trimmed = withScheme.replace(/\/+$/, "");
  return trimmed.endsWith("/v1") ? trimmed : `${trimmed}/v1`;
}

export interface OllamaModelMetadata {
  readonly name: string;
  readonly contextLength: number;
  readonly tools: boolean;
  readonly thinking: boolean;
}

interface OllamaTagsResponse {
  readonly models?: readonly {
    readonly name?: unknown;
    readonly model?: unknown;
    readonly capabilities?: unknown;
    readonly details?: { readonly context_length?: unknown } | null;
  }[];
}

/** Looks the model up in Ollama's native `/api/tags` listing (one level above the `/v1` OpenAI shim). */
export async function describeOllamaModel(
  modelId: string,
  baseUrl: string,
  fetchImpl: typeof fetch,
): Promise<OllamaModelMetadata> {
  const apiRoot = baseUrl.replace(/\/+$/, "").replace(/\/v1$/, "");
  let response: Response;
  try {
    response = await fetchImpl(`${apiRoot}/api/tags`, { signal: AbortSignal.timeout(5_000) });
  } catch (error) {
    throw new ModelProviderError(
      "OLLAMA_UNREACHABLE",
      `Ollama is not reachable at ${apiRoot} (${error instanceof Error ? error.message : String(error)}); is "ollama serve" running?`,
      { cause: error },
    );
  }
  if (!response.ok) {
    throw new ModelProviderError("OLLAMA_UNREACHABLE", `Ollama ${apiRoot}/api/tags answered HTTP ${response.status}`);
  }
  let body: OllamaTagsResponse;
  try {
    body = (await response.json()) as OllamaTagsResponse;
  } catch (error) {
    throw new ModelProviderError(
      "OLLAMA_UNREACHABLE",
      `${apiRoot}/api/tags did not return JSON (${error instanceof Error ? error.message : String(error)}); is that really an Ollama server?`,
      { cause: error },
    );
  }
  if (body === null || typeof body !== "object") {
    throw new ModelProviderError("OLLAMA_UNREACHABLE", `${apiRoot}/api/tags returned an unexpected body`);
  }
  const models = (body.models ?? []).filter(
    (entry): entry is typeof entry & { readonly name: string } => typeof entry.name === "string",
  );
  const match =
    models.find((entry) => entry.name === modelId) ??
    (modelId.includes(":") ? undefined : models.find((entry) => entry.name === `${modelId}:latest`));
  if (match === undefined) {
    const available = models.map((entry) => entry.name).join(", ") || "(none)";
    throw new ModelProviderError(
      "UNKNOWN_MODEL",
      `Ollama at ${apiRoot} has no model "${modelId}"; available: ${available}. Pull it with "ollama pull ${modelId}".`,
    );
  }
  const capabilities = Array.isArray(match.capabilities)
    ? match.capabilities.filter((value): value is string => typeof value === "string")
    : [];
  const contextLength = match.details?.context_length;
  return {
    name: match.name,
    contextLength:
      typeof contextLength === "number" && Number.isSafeInteger(contextLength) && contextLength > 0
        ? contextLength
        : 8_192,
    tools: capabilities.includes("tools"),
    thinking: capabilities.includes("thinking"),
  };
}
