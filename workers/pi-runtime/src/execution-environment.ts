import { normalizeProtocolValue, parseDigest, type Digest, type NormalizedValue } from "@circulusd/protocol-types";

import { PiRuntimeError } from "./errors.ts";
import { snapshotExecutionValue } from "./execution-rpc.ts";
import { snapshotPiGenesisScope, type PiGenesisScope } from "./genesis.ts";
import { decodePiJson } from "./pi-json-codec.ts";
import { exactRecord } from "./validation.ts";

export const PI_EXECUTION_CONFIGURATION_DOMAIN = "circulusd.pi.execution-configuration";
const maximumConfigurationBytes = 262_144;

// This is Loader's JSON environment, separate from binary RPC arguments. It
// contains immutable runtime configuration and no broker or native authority.
export interface PiExecutionEnvironment {
  readonly scope: PiGenesisScope;
  readonly runtimeRevisionDigest: Digest;
  readonly artifactDigest: Digest;
  readonly configurationDigest: Digest;
  readonly configuration: NormalizedValue;
}

export function snapshotPiExecutionEnvironment(input: unknown): PiExecutionEnvironment {
  try {
    const value = exactRecord(input, ["scope", "runtimeRevisionDigest", "artifactDigest", "configurationDigest", "configuration"],
      [], "execution.environment", "INVALID_CONFIGURATION");
    // Bound before cloning/normalizing. decodePiJson rejects bytes and malformed
    // number wrappers; normalized durable JSON keeps fractional schema values
    // represented canonically until actual Pi configuration initialization.
    const configuration = normalizeProtocolValue(snapshotExecutionValue(value.configuration, maximumConfigurationBytes));
    decodePiJson(configuration);
    return { scope: snapshotPiGenesisScope(value.scope), runtimeRevisionDigest: parseDigest(value.runtimeRevisionDigest),
      artifactDigest: parseDigest(value.artifactDigest), configurationDigest: parseDigest(value.configurationDigest), configuration };
  } catch {
    throw new PiRuntimeError("INVALID_CONFIGURATION", "Pi execution environment is invalid or unverified");
  }
}
