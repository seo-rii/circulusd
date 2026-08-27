import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const OPERATIONS = Object.freeze([
  "session.initialize",
  "session.execute",
  "session.read",
  "session.read-events",
  "workspace.initialize",
  "workspace.execute",
  "workspace.lookup-invocation",
  "user.initialize",
  "user.execute",
  "user.read",
  "extension-state.initialize",
  "extension-state.execute",
  "extension-state.read",
  "capability-generation.initialize",
  "capability-generation.execute",
  "capability-generation.assert-current",
  "audit.initialize",
  "audit.execute",
  "audit.read",
]);

export const SCHEMA_SOURCE_FILES = Object.freeze([
  "../../../packages/protocol-types/src/cbor.ts",
  "../../../packages/protocol-types/src/digest.ts",
  "../../../packages/protocol-types/src/errors.ts",
  "../../../packages/protocol-types/src/text.ts",
  "../../../packages/protocol-types/src/types.ts",
  "../../../packages/protocol-types/src/validation.ts",
  "../src/control/audit.ts",
  "../src/control/capability-generation.ts",
  "../src/control/errors.ts",
  "../src/control/extension-state.ts",
  "../src/control/types.ts",
  "../src/control/user.ts",
  "../src/control/validation.ts",
  "../src/host/audit-kernel.ts",
  "../src/host/cells.ts",
  "../src/host/contracts.ts",
  "../src/host/kernel.ts",
  "../src/host/rpc.ts",
  "../src/session/aggregate.ts",
  "../src/session/errors.ts",
  "../src/session/types.ts",
  "../src/workspace/aggregate.ts",
  "../src/workspace/errors.ts",
  "../src/workspace/types.ts",
]);

const TEST_MODULE_URL = new URL("../test/host.rpc.test.ts", import.meta.url);

export function computeHostRpcSchemaDigest(operation) {
  if (!OPERATIONS.includes(operation)) {
    throw new TypeError(`unknown state-host RPC operation ${String(operation)}`);
  }
  const hash = createHash("sha256");
  hash.update("circulusd.state-host.rpc-source.v2\0");
  hash.update(`${operation}\0`);
  for (const relativePath of SCHEMA_SOURCE_FILES) {
    let source = readFileSync(new URL(relativePath, TEST_MODULE_URL), "utf8")
      .replaceAll("\r\n", "\n");
    if (relativePath.endsWith("/rpc.ts")) {
      source = source.replaceAll(/sha256:[0-9a-f]{64}/g, "sha256:<derived>");
    }
    hash.update(`${relativePath}\0${Buffer.byteLength(source).toString()}\0`);
    hash.update(source);
    hash.update("\0");
  }
  return `sha256:${hash.digest("hex")}`;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = Object.fromEntries(
    OPERATIONS.map((operation) => [operation, computeHostRpcSchemaDigest(operation)]),
  );
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}
