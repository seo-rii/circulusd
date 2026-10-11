import { digestStructuredValue } from "@circulusd/protocol-types";
import { expect } from "vitest";

import {
  LowLevelPiAgentEngine, createOpaqueTurnAuthority, createPiAgentCoreFactory,
  type PiAgentCoreAdapterConfiguration,
} from "../src/index.ts";
import { encodePiGenesisConfiguration, type PiGenesisEnvironment, type PiGenesisRequest, type PiGenesisResult } from "../src/genesis.ts";

export const SCOPE = {
  tenantId: `tenant_${"A".repeat(26)}`, workspaceId: `ws_${"A".repeat(26)}`,
  actorSubjectId: `subject_${"A".repeat(26)}`, sessionId: `sess_${"A".repeat(26)}`,
};
export const REVISION = `sha256:${"a".repeat(64)}` as const;
export const CONFIGURATION: PiAgentCoreAdapterConfiguration = {
  systemPrompt: "A deterministic actual Pi genesis test.",
  model: { id: "genesis-model", api: "circulusd-model-gateway", provider: "circulusd", reasoning: false,
    input: ["text"], contextWindow: 4096, maxTokens: 256 },
  tools: [{ name: "echo", description: "Echo a fractional argument",
    parameters: { type: "object", properties: { value: { type: "number", minimum: 0.1 } } }, replayPolicy: "safe" }],
};

export async function environment(): Promise<PiGenesisEnvironment> {
  const configuration = encodePiGenesisConfiguration(CONFIGURATION);
  return { scope: { ...SCOPE }, runtimeRevisionDigest: REVISION, artifactDigest: `sha256:${"b".repeat(64)}`,
    configuration, configurationDigest: await digestStructuredValue("circulusd.pi.genesis-configuration", 1, configuration) };
}

export async function request(): Promise<PiGenesisRequest> {
  const input = { messages: [{ role: "user", content: "첫 번째 메시지" }, { role: "user", content: "second message" }] };
  return { ...SCOPE, turnId: `turn_${"A".repeat(26)}`,
    runtime: { runtimeRevisionDigest: REVISION, engineKind: "low-level", adapterAbiVersion: 2, checkpointSchemaVersion: 2 },
    input, inputDigest: await digestStructuredValue("circulusd.session.turn-input", 1, input) };
}

export async function assertColdFirstBoundary(checkpoint: PiGenesisResult["checkpoint"]) {
  const engine = new LowLevelPiAgentEngine({ sessionId: SCOPE.sessionId, runtimeRevisionDigest: REVISION,
    adapterAbiVersion: 2, checkpointSchemaVersion: 2 }, createPiAgentCoreFactory(CONFIGURATION));
  const boundary = await engine.step({ authority: createOpaqueTurnAuthority(new Uint8Array([1, 2, 3])), checkpoint });
  expect(boundary).toMatchObject({ kind: "effect_request", request: { service: "model", operation: "complete",
    payload: { context: { systemPrompt: CONFIGURATION.systemPrompt, messages: [
      { role: "user", content: "첫 번째 메시지", timestamp: 0 },
      { role: "user", content: "second message", timestamp: 0 },
    ] } } } });
}
