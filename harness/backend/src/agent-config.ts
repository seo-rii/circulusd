import { createHash } from "node:crypto";

import {
  PI_AGENT_CORE_ADAPTER_ABI_VERSION,
  PI_AGENT_CORE_PACKAGE_VERSION,
  type EngineIdentity,
  type PiAgentCoreAdapterConfiguration,
  type PiAgentCoreModelConfiguration,
} from "@circulusd/pi-runtime";
import type { Digest } from "@circulusd/protocol-types";

import type { ToolDefinition } from "./tools.ts";

const BASE_SYSTEM_PROMPT = [
  "You are the circulusd-test agent, a small assistant used to exercise the circulusd Pi runtime engine end to end.",
  "Use the available tools when they help: `calculator` for arithmetic, `now` for the current date/time, `echo` to repeat text",
];
const PYTHON_SYSTEM_PROMPT =
  ", `python` to run Python 3 code for anything that needs real computation, data processing, or files (print what you need to see)";
const CLOSING_SYSTEM_PROMPT = ". Answer concisely, in the same language the user writes in.";

export function buildSystemPrompt(tools: readonly ToolDefinition[]): string {
  const hasPython = tools.some((tool) => tool.name === "python");
  return BASE_SYSTEM_PROMPT.join(" ") + (hasPython ? PYTHON_SYSTEM_PROMPT : "") + CLOSING_SYSTEM_PROMPT;
}

/** The circulusd Pi adapter checkpoint schema this harness targets (see pi-worker.entry.ts). */
export const CHECKPOINT_SCHEMA_VERSION = 2;

export function buildAdapterConfiguration(
  model: PiAgentCoreModelConfiguration,
  tools: readonly ToolDefinition[],
): PiAgentCoreAdapterConfiguration {
  return {
    systemPrompt: buildSystemPrompt(tools),
    model,
    tools: tools.map((tool) => ({
      name: tool.name,
      description: tool.description,
      parameters: tool.parameters,
      replayPolicy: tool.replayPolicy,
    })),
  };
}

/**
 * A content digest over everything that defines the agent runtime for this
 * process (pinned Pi version, adapter ABI, system prompt, model, tools). It
 * plays the role of circulusd's Runtime Revision digest: every checkpoint is
 * bound to it, so a changed prompt or tool set yields a different revision.
 */
export function runtimeRevisionDigest(configuration: PiAgentCoreAdapterConfiguration): Digest {
  const material = JSON.stringify({
    piAgentCore: PI_AGENT_CORE_PACKAGE_VERSION,
    adapterAbiVersion: PI_AGENT_CORE_ADAPTER_ABI_VERSION,
    checkpointSchemaVersion: CHECKPOINT_SCHEMA_VERSION,
    configuration,
  });
  return `sha256:${createHash("sha256").update(material).digest("hex")}`;
}

export function engineIdentity(sessionId: string, digest: Digest): EngineIdentity {
  return {
    sessionId,
    runtimeRevisionDigest: digest,
    adapterAbiVersion: PI_AGENT_CORE_ADAPTER_ABI_VERSION,
    checkpointSchemaVersion: CHECKPOINT_SCHEMA_VERSION,
  };
}
