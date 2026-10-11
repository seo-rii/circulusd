import {
  PiGenesisGenerator,
  assertPiGenesisBinding,
  snapshotPiGenesisEnvironment,
  snapshotPiGenesisRequest,
  type PiGenesisEnvironment,
  type PiGenesisRequest,
} from "./genesis.ts";
import { PiRuntimeError } from "./errors.ts";

// A deployment wrapper imports the real WorkerEntrypoint from cloudflare:workers
// and exports createPiGenesisEntrypointClass(WorkerEntrypoint) as its default.
// Supply a trusted JSON environment from CelldPiGenesisSource. This class exposes
// exactly one genesis RPC; it neither drives turns nor signs native proofs.
export function createPiGenesisEntrypointClass(base: unknown) {
  if (typeof base !== "function") {
    throw new PiRuntimeError("INVALID_CONFIGURATION", "WorkerEntrypoint base is required");
  }
  const WorkerEntrypoint = base as new (context: object, environment: PiGenesisEnvironment) => object;
  return class PiGenesisEntrypoint extends WorkerEntrypoint {
    readonly #environment: PiGenesisEnvironment;
    #generator: Promise<PiGenesisGenerator> | null = null;

    constructor(context: object, environment: PiGenesisEnvironment) {
      super(context, environment);
      this.#environment = snapshotPiGenesisEnvironment(environment);
    }

    async createGenesis(value: PiGenesisRequest) {
      const request = await snapshotPiGenesisRequest(value);
      assertPiGenesisBinding(request, this.#environment);
      this.#generator ??= PiGenesisGenerator.create(this.#environment);
      return (await this.#generator).createGenesis(request);
    }
  };
}
