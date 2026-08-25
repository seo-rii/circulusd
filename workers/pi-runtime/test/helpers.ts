import type {
  NormalizedValue,
} from "@circulusd/protocol-types";
import type {
  AgentCore,
  AgentCoreFactory,
  AgentCoreStepContext,
  AgentCoreTransition,
  EngineIdentity,
  EngineSettlement,
  LowLevelPiAgentEngine,
} from "../src/index.ts";

export const RUNTIME_DIGEST = `sha256:${"a".repeat(64)}` as const;

export function identity(sessionId: string): EngineIdentity {
  return {
    sessionId,
    runtimeRevisionDigest: RUNTIME_DIGEST,
    adapterAbiVersion: 1,
    checkpointSchemaVersion: 1,
  };
}

export function scriptedCore(
  script: (
    context: Readonly<AgentCoreStepContext>,
    call: number,
  ) => AgentCoreTransition | Promise<AgentCoreTransition>,
): { readonly factory: AgentCoreFactory; readonly contexts: AgentCoreStepContext[] } {
  const contexts: AgentCoreStepContext[] = [];
  const factory: AgentCoreFactory = () => {
    return {
      async advance(context) {
        contexts.push(context);
        const call = context.input.kind === "turn_start"
          ? 1
          : context.input.kind === "effect_settlement"
            ? 2
            : context.input.kind === "tool_settlements"
              ? 3
              : contexts.length;
        return script(context, call);
      },
    } satisfies AgentCore;
  };
  return { factory, contexts };
}

export async function genesis(
  engine: LowLevelPiAgentEngine,
  turnId = "turn_01",
  input: unknown = { prompt: "hello" },
) {
  return engine.createGenesisCheckpoint({
    turnId,
    input,
    initialCoreState: { phase: "initial" },
  });
}

export function successSettlement(
  requestDigest: `sha256:${string}`,
  result: NormalizedValue,
): EngineSettlement {
  return {
    requestDigest,
    outcome: { kind: "success", result },
  };
}
