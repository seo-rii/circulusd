import { digestStructuredValue } from "@circulusd/protocol-types";

import { LowLevelPiAgentEngine } from "./engine.ts";
import { PiRuntimeError } from "./errors.ts";
import { PiExecutionEndpoint } from "./execution-endpoint.ts";
import {
  PI_EXECUTION_CONFIGURATION_DOMAIN, snapshotPiExecutionEnvironment, type PiExecutionEnvironment,
} from "./execution-environment.ts";
import {
  invalidExecution, sameExecutionBinding, snapshotExecutionBinding, snapshotExecutionRequest,
  type PiExecutionBinding, type PiExecutionRequest,
} from "./execution-rpc.ts";
import { createPiAgentCoreFactory, type PiAgentCoreAdapterConfiguration } from "./pi-agent-core-adapter.ts";
import { decodePiJson } from "./pi-json-codec.ts";
import { LowLevelPiSessionHostAdapter } from "./session-host-adapter.ts";

// The fixed deployment wrapper supplies the actual cloudflare:workers base.
// RPC exposes exactly exchange; brokers and native proof remain host-owned.
export function createPiExecutionEntrypointClass(base: unknown) {
  if (typeof base !== "function") {
    throw new PiRuntimeError("INVALID_CONFIGURATION", "Pi execution entrypoint base is invalid");
  }
  const WorkerEntrypoint = base as new (context: object, environment: PiExecutionEnvironment) => object;
  return class PiExecutionEntrypoint extends WorkerEntrypoint {
    readonly #environment: PiExecutionEnvironment;
    readonly #binding: PiExecutionBinding;
    #endpoint: Promise<PiExecutionEndpoint> | null = null;

    constructor(context: object, environment: PiExecutionEnvironment) {
      const owned = snapshotPiExecutionEnvironment(environment);
      super(context, environment);
      this.#environment = owned;
      this.#binding = snapshotExecutionBinding({ scope: owned.scope,
        runtimeRevisionDigest: owned.runtimeRevisionDigest, artifactDigest: owned.artifactDigest });
    }

    async exchange(input: PiExecutionRequest) {
      try {
        const request = snapshotExecutionRequest(input);
        if (!sameExecutionBinding(request.binding, this.#binding)) invalidExecution();
        // Install the shared promise before any initialization runs. Pinned
        // celld caches entrypoint instances, and RPC requests can overlap.
        this.#endpoint ??= Promise.resolve().then(() => this.#initialize());
        return await (await this.#endpoint).exchange(request);
      } catch { return invalidExecution(); }
    }

    async #initialize(): Promise<PiExecutionEndpoint> {
      const environment = this.#environment;
      if (await digestStructuredValue(PI_EXECUTION_CONFIGURATION_DOMAIN, 1, environment.configuration) !==
          environment.configurationDigest) invalidExecution();
      const configuration = decodePiJson(environment.configuration) as PiAgentCoreAdapterConfiguration;
      const coreFactory = createPiAgentCoreFactory(configuration);
      return new PiExecutionEndpoint({ binding: this.#binding, createEngine: () => new LowLevelPiSessionHostAdapter(
        new LowLevelPiAgentEngine({ sessionId: environment.scope.sessionId,
          runtimeRevisionDigest: environment.runtimeRevisionDigest, adapterAbiVersion: 2, checkpointSchemaVersion: 2 }, coreFactory),
      ) });
    }
  };
}
