import {
  runAgentLoop,
  runAgentLoopContinue,
  type AgentLoopConfig,
  type AgentMessage,
  type AgentTool,
  type StreamFn,
} from "@earendil-works/pi-agent-core";
import {
  createAssistantMessageEventStream,
  validateToolArguments,
  type Api,
  type AssistantMessage,
  type Context as PiContext,
  type Message,
  type Model,
  type ToolCall,
  type UserMessage,
} from "@earendil-works/pi-ai";
import {
  normalizeProtocolValue,
  type NormalizedValue,
  type ReplayPolicy,
} from "@circulusd/protocol-types";

import { PiRuntimeError } from "./errors.ts";
import {
  boundedProtocolValue,
  boundedSafeInteger,
  exactRecord,
} from "./validation.ts";
import type {
  AgentCoreFactory,
  AgentCoreTransition,
  EffectSettlementOutcome,
} from "./types.ts";

export const PI_AGENT_CORE_PACKAGE_VERSION = "0.84.3" as const;
export const PI_AGENT_CORE_ADAPTER_ABI_VERSION = 2 as const;
export const PI_AGENT_CORE_STATE_VERSION = 2 as const;

const maximumAdapterValueBytes = 4 << 20;

export interface PiAgentCoreModelConfiguration {
  readonly id: string;
  readonly api: string;
  readonly provider: string;
  readonly reasoning: boolean;
  readonly input: readonly ("text" | "image")[];
  readonly contextWindow: number;
  readonly maxTokens: number;
}

export interface PiAgentCoreAdapterConfiguration {
  readonly systemPrompt: string;
  readonly model: PiAgentCoreModelConfiguration;
  readonly tools: readonly PiAgentCoreToolConfiguration[];
}

export interface PiAgentCoreToolConfiguration {
  readonly name: string;
  readonly description: string;
  readonly parameters: unknown;
  readonly replayPolicy: ReplayPolicy;
}

interface PiAgentCoreState {
  readonly [key: string]: NormalizedValue;
  readonly version: typeof PI_AGENT_CORE_STATE_VERSION;
  readonly phase: "ready" | "waiting_model" | "waiting_tools" | "complete" | "failed";
  readonly messages: NormalizedValue[];
  readonly pendingToolCalls: NormalizedValue[];
}

export function createPiAgentCoreInitialState(): NormalizedValue {
  return {
    version: PI_AGENT_CORE_STATE_VERSION,
    phase: "ready",
    messages: [],
    pendingToolCalls: [],
  };
}

export function createPiAgentCoreFactory(
  configuration: PiAgentCoreAdapterConfiguration,
): AgentCoreFactory {
  const normalizedConfiguration = boundedProtocolValue(
    configuration,
    maximumAdapterValueBytes,
    "piAgentCore.configuration",
    "INVALID_CONFIGURATION",
  );
  const configurationRecord = exactRecord(
    normalizedConfiguration,
    ["systemPrompt", "model", "tools"],
    [],
    "piAgentCore.configuration",
    "INVALID_CONFIGURATION",
  );
  if (typeof configurationRecord.systemPrompt !== "string") {
    throw new PiRuntimeError(
      "INVALID_CONFIGURATION",
      "piAgentCore.configuration.systemPrompt must be a string",
    );
  }
  const modelRecord = exactRecord(
    configurationRecord.model,
    ["id", "api", "provider", "reasoning", "input", "contextWindow", "maxTokens"],
    [],
    "piAgentCore.configuration.model",
    "INVALID_CONFIGURATION",
  );
  for (const field of ["id", "api", "provider"] as const) {
    if (
      typeof modelRecord[field] !== "string" ||
      modelRecord[field].length === 0 ||
      modelRecord[field].length > 256
    ) {
      throw new PiRuntimeError(
        "INVALID_CONFIGURATION",
        `piAgentCore.configuration.model.${field} must be a bounded non-empty string`,
      );
    }
  }
  if (typeof modelRecord.reasoning !== "boolean") {
    throw new PiRuntimeError(
      "INVALID_CONFIGURATION",
      "piAgentCore.configuration.model.reasoning must be a boolean",
    );
  }
  if (
    !Array.isArray(modelRecord.input) ||
    modelRecord.input.length === 0 ||
    modelRecord.input.length > 2 ||
    modelRecord.input.some((value) => value !== "text" && value !== "image") ||
    new Set(modelRecord.input).size !== modelRecord.input.length
  ) {
    throw new PiRuntimeError(
      "INVALID_CONFIGURATION",
      "piAgentCore.configuration.model.input must contain unique supported input modes",
    );
  }
  const contextWindow = boundedSafeInteger(
    modelRecord.contextWindow,
    1,
    "piAgentCore.configuration.model.contextWindow",
    "INVALID_CONFIGURATION",
  );
  const maxTokens = boundedSafeInteger(
    modelRecord.maxTokens,
    1,
    "piAgentCore.configuration.model.maxTokens",
    "INVALID_CONFIGURATION",
  );
  if (maxTokens > contextWindow) {
    throw new PiRuntimeError(
      "INVALID_CONFIGURATION",
      "piAgentCore.configuration.model.maxTokens exceeds its context window",
    );
  }
  if (!Array.isArray(configurationRecord.tools)) {
    throw new PiRuntimeError(
      "INVALID_CONFIGURATION",
      "piAgentCore.configuration.tools must be an array",
    );
  }
  const toolNames = new Set<string>();
  const toolDefinitions = configurationRecord.tools.map((tool, index) => {
    const toolRecord = exactRecord(
      tool,
      ["name", "description", "parameters", "replayPolicy"],
      [],
      `piAgentCore.configuration.tools[${index}]`,
      "INVALID_CONFIGURATION",
    );
    if (
      typeof toolRecord.name !== "string" ||
      toolRecord.name.length === 0 ||
      typeof toolRecord.description !== "string" ||
      toolRecord.description.length === 0 ||
      toolRecord.parameters === null ||
      typeof toolRecord.parameters !== "object" ||
      Array.isArray(toolRecord.parameters) ||
      toolRecord.parameters instanceof Uint8Array ||
      (Object.getPrototypeOf(toolRecord.parameters) !== Object.prototype &&
        Object.getPrototypeOf(toolRecord.parameters) !== null) ||
      (toolRecord.replayPolicy !== "safe" &&
        toolRecord.replayPolicy !== "idempotency-key" &&
        toolRecord.replayPolicy !== "never" &&
        toolRecord.replayPolicy !== "confirm")
    ) {
      throw new PiRuntimeError(
        "INVALID_CONFIGURATION",
        `piAgentCore.configuration.tools[${index}] is invalid`,
      );
    }
    if (toolNames.has(toolRecord.name)) {
      throw new PiRuntimeError(
        "INVALID_CONFIGURATION",
        `piAgentCore.configuration.tools contains duplicate name ${toolRecord.name}`,
      );
    }
    const parameters = normalizeProtocolValue(toolRecord.parameters);
    const schemaNodes: NormalizedValue[] = [parameters];
    while (schemaNodes.length > 0) {
      const node = schemaNodes.pop();
      if (node instanceof Uint8Array) {
        throw new PiRuntimeError(
          "INVALID_CONFIGURATION",
          `piAgentCore.configuration.tools[${index}].parameters is not JSON`,
        );
      }
      if (Array.isArray(node)) {
        schemaNodes.push(...node);
      } else if (node !== null && typeof node === "object") {
        schemaNodes.push(...Object.values(node));
      }
    }
    toolNames.add(toolRecord.name);
    return Object.freeze({
      name: toolRecord.name,
      description: toolRecord.description,
      parameters: structuredClone(parameters),
      replayPolicy: toolRecord.replayPolicy,
    });
  });
  const toolRegistry = new Map(toolDefinitions.map((tool) => [tool.name, tool]));
  const runtimeTools = toolDefinitions.map((tool) => Object.freeze({
    name: tool.name,
    label: tool.name,
    description: tool.description,
    parameters: structuredClone(tool.parameters),
    executionMode: "sequential" as const,
    async execute() {
      throw new Error("Pi tools execute only through the durable external effect boundary");
    },
  })) as unknown as AgentTool<any>[];
  const advertisedTools = toolDefinitions.map((tool) => Object.freeze({
    name: tool.name,
    description: tool.description,
    parameters: structuredClone(tool.parameters),
  }));

  const systemPrompt = configurationRecord.systemPrompt;
  const modelConfiguration = Object.freeze({
    id: modelRecord.id as string,
    api: modelRecord.api as string,
    provider: modelRecord.provider as string,
    reasoning: modelRecord.reasoning,
    input: [...(modelRecord.input as ("text" | "image")[])],
    contextWindow,
    maxTokens,
  });
  const piModel: Model<Api> = Object.freeze({
    id: modelConfiguration.id,
    name: modelConfiguration.id,
    api: modelConfiguration.api,
    provider: modelConfiguration.provider,
    baseUrl: "",
    reasoning: modelConfiguration.reasoning,
    input: [...modelConfiguration.input],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: modelConfiguration.contextWindow,
    maxTokens: modelConfiguration.maxTokens,
  });
  const loopConfiguration: AgentLoopConfig = {
    model: piModel,
    convertToLlm(messages) {
      return messages as Message[];
    },
    shouldStopAfterTurn() {
      return true;
    },
    toolExecution: "sequential",
  };

  return (factoryContext) => {
    if (
      factoryContext.adapterAbiVersion !== PI_AGENT_CORE_ADAPTER_ABI_VERSION ||
      factoryContext.checkpointSchemaVersion !== PI_AGENT_CORE_STATE_VERSION
    ) {
      throw new PiRuntimeError(
        "INVALID_CONFIGURATION",
        `Pi Agent Core adapter ABI v${PI_AGENT_CORE_ADAPTER_ABI_VERSION} and state v${PI_AGENT_CORE_STATE_VERSION} require exact matching runtime identity versions`,
      );
    }
    return {
    async advance(context): Promise<AgentCoreTransition> {
      const stateRecord = exactRecord(
        context.state,
        ["version", "phase", "messages", "pendingToolCalls"],
        [],
        "piAgentCore.state",
        "CORE_OUTPUT_INVALID",
      );
      if (stateRecord.version !== PI_AGENT_CORE_STATE_VERSION) {
        throw new Error("Pi Agent Core state version is unsupported");
      }
      if (
        stateRecord.phase !== "ready" &&
        stateRecord.phase !== "waiting_model" &&
        stateRecord.phase !== "waiting_tools" &&
        stateRecord.phase !== "complete" &&
        stateRecord.phase !== "failed"
      ) {
        throw new Error("Pi Agent Core state phase is unsupported");
      }
      if (!Array.isArray(stateRecord.messages) || !Array.isArray(stateRecord.pendingToolCalls)) {
        throw new Error("Pi Agent Core state message and tool queues must be arrays");
      }
      const state: PiAgentCoreState = {
        version: PI_AGENT_CORE_STATE_VERSION,
        phase: stateRecord.phase,
        messages: stateRecord.messages.map((message) => normalizeProtocolValue(message)),
        pendingToolCalls: stateRecord.pendingToolCalls.map((call) => normalizeProtocolValue(call)),
      };

      if (context.input.kind === "turn_start") {
        if (state.phase !== "ready" || state.messages.length !== 0) {
          return {
            kind: "turn_error",
            state: { ...state, phase: "failed" },
            error: {
              code: "PI_STATE_MISMATCH",
              message: "Pi turn start requires a fresh adapter state",
              retryable: false,
            },
          };
        }
        const inputRecord = exactRecord(
          context.input.input,
          ["prompt", "timestamp"],
          [],
          "piAgentCore.turnInput",
          "CORE_OUTPUT_INVALID",
        );
        if (typeof inputRecord.prompt !== "string") {
          throw new Error("Pi turn prompt must be a string");
        }
        const timestamp = boundedSafeInteger(
          inputRecord.timestamp,
          0,
          "piAgentCore.turnInput.timestamp",
          "CORE_OUTPUT_INVALID",
        );
        const prompt: UserMessage = {
          role: "user",
          content: inputRecord.prompt,
          timestamp,
        };
        let capturedContext: PiContext | undefined;
        let modelCalls = 0;
        let modelMismatch = false;
        const captureModelBoundary: StreamFn = (model, piContext) => {
          modelCalls += 1;
          if (
            model.id !== piModel.id ||
            model.api !== piModel.api ||
            model.provider !== piModel.provider
          ) {
            modelMismatch = true;
          }
          capturedContext = {
            ...(piContext.systemPrompt === undefined ? {} : { systemPrompt: piContext.systemPrompt }),
            messages: structuredClone(piContext.messages),
            tools: structuredClone(advertisedTools) as unknown as NonNullable<PiContext["tools"]>,
          };
          const stream = createAssistantMessageEventStream();
          const aborted: AssistantMessage = {
            role: "assistant",
            content: [],
            api: piModel.api,
            provider: piModel.provider,
            model: piModel.id,
            usage: {
              input: 0,
              output: 0,
              cacheRead: 0,
              cacheWrite: 0,
              totalTokens: 0,
              cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
            },
            stopReason: "aborted",
            errorMessage: "model request captured by the bounded adapter",
            timestamp,
          };
          stream.push({ type: "error", reason: "aborted", error: aborted });
          return stream;
        };
        await runAgentLoop(
          [prompt],
          { systemPrompt, messages: [], tools: runtimeTools },
          loopConfiguration,
          async () => undefined,
          context.signal,
          captureModelBoundary,
        );
        if (capturedContext === undefined || modelCalls !== 1) {
          throw new Error("Pi did not produce exactly one bounded model request");
        }
        if (modelMismatch) {
          return {
            kind: "turn_error",
            state: { ...state, phase: "failed" },
            error: {
              code: "PI_MODEL_REQUEST_MISMATCH",
              message: "Pi invoked a model outside the immutable runtime configuration",
              retryable: false,
            },
          };
        }
        const normalizedContext = boundedProtocolValue(
          capturedContext,
          maximumAdapterValueBytes,
          "piAgentCore.modelContext",
          "CORE_OUTPUT_INVALID",
        ) as { readonly messages: NormalizedValue[] } & NormalizedValue;
        return {
          kind: "model_request",
          state: {
            version: PI_AGENT_CORE_STATE_VERSION,
            phase: "waiting_model",
            messages: structuredClone(normalizedContext.messages),
            pendingToolCalls: [],
          },
          request: {
            service: "model",
            operation: "complete",
            replayPolicy: "never",
            payload: {
              protocol: "pi-agent-core",
              version: 1,
              packageVersion: PI_AGENT_CORE_PACKAGE_VERSION,
              model: modelConfiguration,
              context: normalizedContext,
            },
          },
        };
      }

      if (context.input.kind === "effect_settlement") {
        if (
          state.phase !== "waiting_model" ||
          context.input.request.service !== "model" ||
          context.input.request.operation !== "complete"
        ) {
          return {
            kind: "turn_error",
            state: { ...state, phase: "failed" },
            error: {
              code: "PI_STATE_MISMATCH",
              message: "Pi model settlement does not match the adapter state",
              retryable: false,
            },
          };
        }
        if (context.input.settlement.kind !== "success") {
          const settlement: EffectSettlementOutcome = context.input.settlement;
          return {
            kind: "turn_error",
            state: { ...state, phase: "failed" },
            error: {
              code: "PI_MODEL_SETTLEMENT_FAILED",
              message: settlement.kind === "error" ? settlement.message : settlement.reason,
              retryable: false,
            },
          };
        }
        const settlementRecord = exactRecord(
          context.input.settlement.result,
          ["version", "message"],
          [],
          "piAgentCore.modelSettlement",
          "CORE_OUTPUT_INVALID",
        );
        if (settlementRecord.version !== 1) {
          throw new Error("Pi model settlement version is unsupported");
        }
        const messageRecord = exactRecord(
          settlementRecord.message,
          ["role", "content", "api", "provider", "model", "usage", "stopReason", "timestamp"],
          ["responseModel", "responseId", "errorMessage", "rawStopReason", "endTurn"],
          "piAgentCore.modelSettlement.message",
          "CORE_OUTPUT_INVALID",
        );
        if (
          messageRecord.role !== "assistant" ||
          typeof messageRecord.api !== "string" ||
          typeof messageRecord.provider !== "string" ||
          typeof messageRecord.model !== "string" ||
          !Array.isArray(messageRecord.content)
        ) {
          throw new Error("Pi model settlement assistant message is invalid");
        }
        const metadataIsValid = [
          messageRecord.responseModel,
          messageRecord.responseId,
          messageRecord.errorMessage,
          messageRecord.rawStopReason,
        ].every((value) => value === undefined || typeof value === "string") &&
          (messageRecord.endTurn === undefined || typeof messageRecord.endTurn === "boolean");
        if (!metadataIsValid) {
          return {
            kind: "turn_error",
            state: { ...state, phase: "failed" },
            error: {
              code: "PI_MODEL_RESPONSE_INVALID",
              message: "Pi model response metadata is invalid",
              retryable: false,
            },
          };
        }
        boundedSafeInteger(
          messageRecord.timestamp,
          0,
          "piAgentCore.modelSettlement.message.timestamp",
          "CORE_OUTPUT_INVALID",
        );
        const usageRecord = exactRecord(
          messageRecord.usage,
          ["input", "output", "cacheRead", "cacheWrite", "totalTokens", "cost"],
          ["cacheWrite1h", "reasoning"],
          "piAgentCore.modelSettlement.message.usage",
          "CORE_OUTPUT_INVALID",
        );
        const costRecord = exactRecord(
          usageRecord.cost,
          ["input", "output", "cacheRead", "cacheWrite", "total"],
          [],
          "piAgentCore.modelSettlement.message.usage.cost",
          "CORE_OUTPUT_INVALID",
        );
        const usageIsValid = [
          usageRecord.input,
          usageRecord.output,
          usageRecord.cacheRead,
          usageRecord.cacheWrite,
          usageRecord.totalTokens,
          usageRecord.cacheWrite1h,
          usageRecord.reasoning,
        ].every((value) => value === undefined ||
          (typeof value === "number" && Number.isSafeInteger(value) && value >= 0)) &&
          [
            costRecord.input,
            costRecord.output,
            costRecord.cacheRead,
            costRecord.cacheWrite,
            costRecord.total,
          ].every((value) =>
            typeof value === "number" && Number.isFinite(value) && value >= 0
          );
        if (!usageIsValid) {
          return {
            kind: "turn_error",
            state: { ...state, phase: "failed" },
            error: {
              code: "PI_MODEL_RESPONSE_INVALID",
              message: "Pi model response usage is invalid",
              retryable: false,
            },
          };
        }
        if (
          messageRecord.api !== modelConfiguration.api ||
          messageRecord.provider !== modelConfiguration.provider ||
          messageRecord.model !== modelConfiguration.id
        ) {
          return {
            kind: "turn_error",
            state: { ...state, phase: "failed" },
            error: {
              code: "PI_MODEL_RESPONSE_MISMATCH",
              message: "Pi model response does not match the durable request",
              retryable: false,
            },
          };
        }
        const stopReason = messageRecord.stopReason;
        if (stopReason === "aborted" || stopReason === "error") {
          const message = typeof messageRecord.errorMessage === "string"
            ? messageRecord.errorMessage
            : `Pi model ${stopReason}`;
          return {
            kind: "turn_error",
            state: {
              version: PI_AGENT_CORE_STATE_VERSION,
              phase: "failed",
              messages: [...state.messages, normalizeProtocolValue(messageRecord)],
              pendingToolCalls: [],
            },
            error: {
              code: stopReason === "aborted" ? "PI_MODEL_ABORTED" : "PI_MODEL_ERROR",
              message,
              retryable: false,
            },
          };
        }
        if (stopReason !== "stop" && stopReason !== "length" && stopReason !== "toolUse") {
          return {
            kind: "turn_error",
            state: { ...state, phase: "failed" },
            error: {
              code: "PI_MODEL_RESPONSE_UNSUPPORTED",
              message: "Pi model response stop reason is unsupported",
              retryable: false,
            },
          };
        }
        const toolCalls: NormalizedValue[] = [];
        const validatedToolCalls = new Map<string, NormalizedValue>();
        const toolCallIds = new Set<string>();
        for (const priorMessage of state.messages) {
          if (
            priorMessage === null ||
            typeof priorMessage !== "object" ||
            Array.isArray(priorMessage) ||
            priorMessage instanceof Uint8Array ||
            priorMessage.role !== "assistant" ||
            !Array.isArray(priorMessage.content)
          ) {
            continue;
          }
          for (const priorBlock of priorMessage.content) {
            if (
              priorBlock !== null &&
              typeof priorBlock === "object" &&
              !Array.isArray(priorBlock) &&
              !(priorBlock instanceof Uint8Array) &&
              priorBlock.type === "toolCall" &&
              typeof priorBlock.id === "string"
            ) {
              toolCallIds.add(priorBlock.id);
            }
          }
        }
        for (const [index, block] of messageRecord.content.entries()) {
          const contentRecord = exactRecord(
            block,
            ["type"],
            [
              "text",
              "textSignature",
              "thinking",
              "thinkingSignature",
              "redacted",
              "id",
              "name",
              "arguments",
              "thoughtSignature",
              "namespace",
            ],
            `piAgentCore.modelSettlement.message.content[${index}]`,
            "CORE_OUTPUT_INVALID",
          );
          if (contentRecord.type === "text") {
            const textRecord = exactRecord(
              block,
              ["type", "text"],
              ["textSignature"],
              `piAgentCore.modelSettlement.message.content[${index}]`,
              "CORE_OUTPUT_INVALID",
            );
            if (
              typeof textRecord.text !== "string" ||
              (textRecord.textSignature !== undefined &&
                typeof textRecord.textSignature !== "string")
            ) {
              throw new Error("Pi text content is invalid");
            }
            continue;
          }
          if (contentRecord.type === "thinking" && modelConfiguration.reasoning) {
            const thinkingRecord = exactRecord(
              block,
              ["type", "thinking"],
              ["thinkingSignature", "redacted"],
              `piAgentCore.modelSettlement.message.content[${index}]`,
              "CORE_OUTPUT_INVALID",
            );
            if (
              typeof thinkingRecord.thinking !== "string" ||
              (thinkingRecord.thinkingSignature !== undefined &&
                typeof thinkingRecord.thinkingSignature !== "string") ||
              (thinkingRecord.redacted !== undefined &&
                typeof thinkingRecord.redacted !== "boolean")
            ) {
              throw new Error("Pi thinking content is invalid");
            }
            continue;
          }
          if (contentRecord.type === "toolCall") {
            const toolCallRecord = exactRecord(
              block,
              ["type", "id", "name", "arguments"],
              ["thoughtSignature", "namespace"],
              `piAgentCore.modelSettlement.message.content[${index}]`,
              "CORE_OUTPUT_INVALID",
            );
            if (
              typeof toolCallRecord.id !== "string" ||
              toolCallRecord.id.length === 0 ||
              typeof toolCallRecord.name !== "string" ||
              toolCallRecord.name.length === 0 ||
              toolCallRecord.name.length > 256 ||
              toolCallRecord.arguments === null ||
              typeof toolCallRecord.arguments !== "object" ||
              Array.isArray(toolCallRecord.arguments) ||
              toolCallRecord.arguments instanceof Uint8Array ||
              (Object.getPrototypeOf(toolCallRecord.arguments) !== Object.prototype &&
                Object.getPrototypeOf(toolCallRecord.arguments) !== null) ||
              (toolCallRecord.thoughtSignature !== undefined &&
                typeof toolCallRecord.thoughtSignature !== "string") ||
              (toolCallRecord.namespace !== undefined &&
                typeof toolCallRecord.namespace !== "string")
            ) {
              return {
                kind: "turn_error",
                state: { ...state, phase: "failed" },
                error: {
                  code: "PI_TOOL_CALL_INVALID",
                  message: "Pi tool call identity or arguments are invalid",
                  retryable: false,
                },
              };
            }
            if (toolCallIds.has(toolCallRecord.id)) {
              return {
                kind: "turn_error",
                state: { ...state, phase: "failed" },
                error: {
                  code: "PI_TOOL_CALL_DUPLICATE",
                  message: "Pi model response contains a duplicate tool call identity",
                  retryable: false,
                },
              };
            }
            if (!toolRegistry.has(toolCallRecord.name)) {
              return {
                kind: "turn_error",
                state: { ...state, phase: "failed" },
                error: {
                  code: "PI_TOOL_UNREGISTERED",
                  message: "Pi model response requested an unregistered tool",
                  retryable: false,
                },
              };
            }
            const argumentNodes: NormalizedValue[] = [
              normalizeProtocolValue(toolCallRecord.arguments),
            ];
            let containsNonJsonArgument = false;
            while (argumentNodes.length > 0) {
              const node = argumentNodes.pop();
              if (node instanceof Uint8Array) {
                containsNonJsonArgument = true;
                break;
              }
              if (Array.isArray(node)) {
                argumentNodes.push(...node);
              } else if (node !== null && typeof node === "object") {
                argumentNodes.push(...Object.values(node));
              }
            }
            let validatedArguments: NormalizedValue;
            try {
              if (containsNonJsonArgument) throw new Error("tool arguments are not JSON");
              const runtimeTool = runtimeTools.find((tool) => tool.name === toolCallRecord.name);
              if (runtimeTool === undefined) throw new Error("registered runtime tool is missing");
              validatedArguments = normalizeProtocolValue(validateToolArguments(
                runtimeTool,
                {
                  ...toolCallRecord,
                  arguments: structuredClone(toolCallRecord.arguments),
                } as ToolCall,
              ));
              if (
                validatedArguments === null ||
                typeof validatedArguments !== "object" ||
                Array.isArray(validatedArguments) ||
                validatedArguments instanceof Uint8Array
              ) {
                throw new Error("validated tool arguments are not a record");
              }
            } catch {
              return {
                kind: "turn_error",
                state: { ...state, phase: "failed" },
                error: {
                  code: "PI_TOOL_CALL_INVALID",
                  message: "Pi tool call arguments failed the registered schema",
                  retryable: false,
                },
              };
            }
            const validatedToolCall = normalizeProtocolValue({
              ...toolCallRecord,
              arguments: validatedArguments,
            });
            toolCallIds.add(toolCallRecord.id);
            toolCalls.push(normalizeProtocolValue(toolCallRecord));
            validatedToolCalls.set(toolCallRecord.id, validatedToolCall);
            continue;
          }
          throw new Error("Pi model-only settlement contains unsupported content");
        }
        const assistant = normalizeProtocolValue(messageRecord) as unknown as AssistantMessage;
        if ((toolCalls.length > 0) !== (stopReason === "toolUse")) {
          return {
            kind: "turn_error",
            state: { ...state, phase: "failed" },
            error: {
              code: "PI_TOOL_CALL_STOP_REASON_MISMATCH",
              message: "Pi tool calls do not match the model stop reason",
              retryable: false,
            },
          };
        }
        if (toolCalls.length > 0) {
          const durableAssistant = normalizeProtocolValue(messageRecord);
          return {
            kind: "tool_requests",
            state: {
              version: PI_AGENT_CORE_STATE_VERSION,
              phase: "waiting_tools",
              messages: [...state.messages, durableAssistant],
              pendingToolCalls: structuredClone(toolCalls),
            },
            requests: toolCalls.map((toolCall) => ({
              service: "external-tool" as const,
              operation: "call",
              replayPolicy: toolRegistry.get(
                (toolCall as { readonly name: string }).name,
              )!.replayPolicy,
              payload: {
                protocol: "pi-agent-core",
                version: 1,
                toolCall: structuredClone(validatedToolCalls.get(
                  (toolCall as { readonly id: string }).id,
                )!),
              },
            })),
          };
        }
        let modelCalls = 0;
        const settledModelStream: StreamFn = () => {
          modelCalls += 1;
          const stream = createAssistantMessageEventStream();
          stream.push({
            type: "done",
            reason: stopReason,
            message: structuredClone(assistant),
          });
          return stream;
        };
        const messages = await runAgentLoopContinue(
          {
            systemPrompt,
            messages: state.messages.map((message) => structuredClone(message)) as unknown as Message[],
            tools: [],
          },
          loopConfiguration,
          async () => undefined,
          context.signal,
          settledModelStream,
        );
        if (modelCalls !== 1 || messages.length !== 1 || messages[0]?.role !== "assistant") {
          throw new Error("Pi model settlement did not complete exactly one bounded turn");
        }
        const completedMessage = boundedProtocolValue(
          messages[0] as AgentMessage,
          maximumAdapterValueBytes,
          "piAgentCore.completedMessage",
          "CORE_OUTPUT_INVALID",
        );
        return {
          kind: "turn_complete",
          state: {
            version: PI_AGENT_CORE_STATE_VERSION,
            phase: "complete",
            messages: [...state.messages, completedMessage],
            pendingToolCalls: [],
          },
          result: {
            version: 1,
            message: structuredClone(completedMessage),
          },
        };
      }

      if (context.input.kind === "tool_settlements") {
        if (
          state.phase !== "waiting_tools" ||
          state.pendingToolCalls.length === 0 ||
          context.input.results.length !== state.pendingToolCalls.length
        ) {
          return {
            kind: "turn_error",
            state: { ...state, phase: "failed" },
            error: {
              code: "PI_TOOL_SETTLEMENT_MISMATCH",
              message: "Pi tool settlements do not match the durable tool queue",
              retryable: false,
            },
          };
        }
        const toolResultMessages: NormalizedValue[] = [];
        for (const [index, entry] of context.input.results.entries()) {
          const expectedCall = state.pendingToolCalls[index];
          // beforeToolCall may patch operation/payload. The enclosing engine already
          // correlates that dispatched intent by digest and ordinal; the original
          // durable Pi call remains the transcript identity checked below.
          if (entry.request.service !== "external-tool" || entry.settlement.kind !== "success") {
            return {
              kind: "turn_error",
              state: { ...state, phase: "failed" },
              error: {
                code: "PI_TOOL_SETTLEMENT_MISMATCH",
                message: "Pi tool settlement identity, input, or outcome is invalid",
                retryable: false,
              },
            };
          }
          const expectedCallRecord = exactRecord(
            expectedCall,
            ["type", "id", "name", "arguments"],
            ["thoughtSignature", "namespace"],
            `piAgentCore.state.pendingToolCalls[${index}]`,
            "CORE_OUTPUT_INVALID",
          );
          const resultRecord = exactRecord(
            entry.settlement.result,
            ["version", "toolCallId", "toolName", "content", "isError", "timestamp"],
            ["details"],
            `piAgentCore.toolSettlements[${index}].result`,
            "CORE_OUTPUT_INVALID",
          );
          if (
            resultRecord.version !== 1 ||
            resultRecord.toolCallId !== expectedCallRecord.id ||
            resultRecord.toolName !== expectedCallRecord.name ||
            !Array.isArray(resultRecord.content) ||
            typeof resultRecord.isError !== "boolean"
          ) {
            return {
              kind: "turn_error",
              state: { ...state, phase: "failed" },
              error: {
                code: "PI_TOOL_RESULT_INVALID",
                message: "Pi tool result does not match its durable tool call",
                retryable: false,
              },
            };
          }
          const timestamp = boundedSafeInteger(
            resultRecord.timestamp,
            0,
            `piAgentCore.toolSettlements[${index}].result.timestamp`,
            "CORE_OUTPUT_INVALID",
          );
          const content: NormalizedValue[] = [];
          let invalidContent = false;
          for (const [contentIndex, block] of resultRecord.content.entries()) {
            const contentRecord = exactRecord(
              block,
              ["type"],
              ["text", "textSignature", "data", "mimeType"],
              `piAgentCore.toolSettlements[${index}].result.content[${contentIndex}]`,
              "CORE_OUTPUT_INVALID",
            );
            if (contentRecord.type === "text") {
              const textRecord = exactRecord(
                block,
                ["type", "text"],
                ["textSignature"],
                `piAgentCore.toolSettlements[${index}].result.content[${contentIndex}]`,
                "CORE_OUTPUT_INVALID",
              );
              if (
                typeof textRecord.text !== "string" ||
                (textRecord.textSignature !== undefined &&
                  typeof textRecord.textSignature !== "string")
              ) {
                invalidContent = true;
                break;
              }
              content.push(normalizeProtocolValue(textRecord));
              continue;
            }
            if (contentRecord.type === "image" && modelConfiguration.input.includes("image")) {
              const imageRecord = exactRecord(
                block,
                ["type", "data", "mimeType"],
                [],
                `piAgentCore.toolSettlements[${index}].result.content[${contentIndex}]`,
                "CORE_OUTPUT_INVALID",
              );
              if (typeof imageRecord.data !== "string" || typeof imageRecord.mimeType !== "string") {
                invalidContent = true;
                break;
              }
              content.push(normalizeProtocolValue(imageRecord));
              continue;
            }
            invalidContent = true;
            break;
          }
          if (invalidContent) {
            return {
              kind: "turn_error",
              state: { ...state, phase: "failed" },
              error: {
                code: "PI_TOOL_RESULT_INVALID",
                message: "Pi tool result contains unsupported or malformed content",
                retryable: false,
              },
            };
          }
          toolResultMessages.push(normalizeProtocolValue({
            role: "toolResult",
            toolCallId: resultRecord.toolCallId,
            toolName: resultRecord.toolName,
            content,
            ...(resultRecord.details === undefined
              ? {}
              : { details: normalizeProtocolValue(resultRecord.details) }),
            isError: resultRecord.isError,
            timestamp,
          }));
        }
        const continuationMessages = [...state.messages, ...toolResultMessages];
        let capturedContext: PiContext | undefined;
        let modelCalls = 0;
        let modelMismatch = false;
        const timestamp = (toolResultMessages.at(-1) as { readonly timestamp: number }).timestamp;
        const captureModelBoundary: StreamFn = (model, piContext) => {
          modelCalls += 1;
          if (
            model.id !== piModel.id ||
            model.api !== piModel.api ||
            model.provider !== piModel.provider
          ) {
            modelMismatch = true;
          }
          capturedContext = {
            ...(piContext.systemPrompt === undefined ? {} : { systemPrompt: piContext.systemPrompt }),
            messages: structuredClone(piContext.messages),
            tools: structuredClone(advertisedTools) as unknown as NonNullable<PiContext["tools"]>,
          };
          const stream = createAssistantMessageEventStream();
          const aborted: AssistantMessage = {
            role: "assistant",
            content: [],
            api: piModel.api,
            provider: piModel.provider,
            model: piModel.id,
            usage: {
              input: 0,
              output: 0,
              cacheRead: 0,
              cacheWrite: 0,
              totalTokens: 0,
              cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
            },
            stopReason: "aborted",
            errorMessage: "model request captured by the bounded adapter",
            timestamp,
          };
          stream.push({ type: "error", reason: "aborted", error: aborted });
          return stream;
        };
        await runAgentLoopContinue(
          {
            systemPrompt,
            messages: continuationMessages.map((message) =>
              structuredClone(message)
            ) as unknown as Message[],
            tools: runtimeTools,
          },
          loopConfiguration,
          async () => undefined,
          context.signal,
          captureModelBoundary,
        );
        if (capturedContext === undefined || modelCalls !== 1 || modelMismatch) {
          return {
            kind: "turn_error",
            state: { ...state, phase: "failed" },
            error: {
              code: "PI_MODEL_REQUEST_MISMATCH",
              message: "Pi tool continuation did not produce one configured model request",
              retryable: false,
            },
          };
        }
        const normalizedContext = boundedProtocolValue(
          capturedContext,
          maximumAdapterValueBytes,
          "piAgentCore.modelContext",
          "CORE_OUTPUT_INVALID",
        ) as { readonly messages: NormalizedValue[] } & NormalizedValue;
        return {
          kind: "model_request",
          state: {
            version: PI_AGENT_CORE_STATE_VERSION,
            phase: "waiting_model",
            messages: structuredClone(normalizedContext.messages),
            pendingToolCalls: [],
          },
          request: {
            service: "model",
            operation: "complete",
            replayPolicy: "never",
            payload: {
              protocol: "pi-agent-core",
              version: 1,
              packageVersion: PI_AGENT_CORE_PACKAGE_VERSION,
              model: modelConfiguration,
              context: normalizedContext,
            },
          },
        };
      }

      return {
        kind: "turn_error",
        state: { ...state, phase: "failed" },
        error: {
          code: "PI_STATE_MISMATCH",
          message: "Pi adapter received an unsupported continuation",
          retryable: false,
        },
      };
    },
    };
  };
}
