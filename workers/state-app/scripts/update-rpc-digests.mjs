#!/usr/bin/env node
// Updates every pinned copy of the host RPC schema digests after a schema
// source changes. The digests are pinned in src/host/rpc.ts and repeated in
// tracked files: TypeScript and Go tests, the Go state-app client, and the
// signed ingress fixtures, whose response MACs are recomputed once the stored
// MAC has been reproduced. With --check, stale digests are only reported and
// the exit status is 1.
import { execFileSync } from "node:child_process";
import { createHash, createHmac } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { computeHostRpcSchemaDigest } from "./generate-rpc-digests.mjs";

const RPC_SOURCE = "workers/state-app/src/host/rpc.ts";
const FIXTURE_DIRECTORY = "packages/protocol-types/fixtures/";
const PINNED_DIGEST = /"([a-z.-]+)": Object\.freeze\(\{\s*schemaDigest:\s*"(sha256:[0-9a-f]{64})"/g;
const RESPONSE_KEY_DOMAIN = "circulusd.state-ingress.key.response.v1\0";
// Response MAC domains of the signed ingress paths, as in src/host/ingress.ts.
const RESPONSE_MAC_DOMAINS = Object.freeze({
  "/circulusd/state/v1/session-events:read": "circulusd.state-ingress.response.v1",
  "/circulusd/state/v1/session-dispatch-start:claim": "circulusd.state-dispatch-start-ingress.response.v1",
  "/circulusd/state/v1/session-blob:read": "circulusd.state-blob-ingress.response.v1",
  "/circulusd/state/v1/session-turn:admit": "circulusd.state-turn-ingress.response.v1",
  "/circulusd/state/v1/session-turn:plan": "circulusd.state-turn-plan-ingress.response.v1",
  "/circulusd/state/v1/session-broker:execute": "circulusd.state-broker-ingress.response.v1",
});

const hex = (text) => Buffer.from(text, "utf8").toString("hex");
const sha256 = (bytes) => createHash("sha256").update(bytes).digest();

function lengthPrefixed(parts) {
  return Buffer.concat(parts.map((part) => {
    const bytes = typeof part === "string" ? Buffer.from(part, "utf8") : part;
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    return Buffer.concat([length, bytes]);
  }));
}

/** Returns a map from each stale pinned digest to its current value. */
export function staleDigests(rpcSource, compute = computeHostRpcSchemaDigest) {
  const pinned = [...rpcSource.matchAll(PINNED_DIGEST)];
  if (pinned.length === 0) {
    throw new Error(`${RPC_SOURCE}: no pinned schema digests found`);
  }
  if (new Set(pinned.map(([, operation]) => operation)).size !== pinned.length) {
    throw new Error(`${RPC_SOURCE}: an operation pins more than one schema digest`);
  }
  const replacements = new Map();
  for (const [, operation, current] of pinned) {
    const next = compute(operation);
    if (next !== current) {
      replacements.set(current, next);
    }
  }
  return replacements;
}

/** Computes a signed ingress fixture's response MAC. */
export function responseMac(fixture) {
  const domain = RESPONSE_MAC_DOMAINS[fixture.path];
  if (domain === undefined) {
    throw new Error(`no response MAC domain is known for ${fixture.path}`);
  }
  const key = createHmac("sha256", Buffer.from(fixture.rootKeyHex, "hex"))
    .update(RESPONSE_KEY_DOMAIN)
    .digest();
  return createHmac("sha256", key).update(lengthPrefixed([
    domain,
    fixture.keyId,
    fixture.response.requestId,
    sha256(Buffer.from(fixture.requestCborHex, "hex")),
    String(fixture.responseStatus),
    fixture.contentType,
    sha256(Buffer.from(fixture.responseCborHex, "hex")),
  ])).digest("hex");
}

function replaceAll(text, replacements, encode = (value) => value) {
  let result = text;
  for (const [current, next] of replacements) {
    result = result.replaceAll(encode(current), encode(next));
  }
  return result;
}

/**
 * Rewrites a signed ingress fixture. Digests keep their length, so the CBOR
 * text heads stay valid, and only the response MAC changes. Request bytes are
 * authenticated by a request MAC this script cannot recompute, so a fixture
 * whose request carries a stale digest is refused.
 */
export function rewriteFixture(name, text, replacements) {
  const before = JSON.parse(text);
  if (responseMac(before) !== before.responseMacHex) {
    throw new Error(`${name}: the response MAC formula does not reproduce the stored MAC`);
  }
  const rewritten = replaceAll(replaceAll(text, replacements), replacements, hex);
  const after = JSON.parse(rewritten);
  if (after.requestCborHex !== before.requestCborHex) {
    throw new Error(`${name}: the request bytes carry a stale digest; update requestMacHex by hand`);
  }
  return rewritten.replace(before.responseMacHex, responseMac(after));
}

function trackedFilesContaining(repository, values) {
  const patterns = values.flatMap((value) => ["-e", value]);
  try {
    return execFileSync("git", ["grep", "-l", "-F", ...patterns], {
      cwd: repository,
      encoding: "utf8",
    }).split("\n").filter(Boolean);
  } catch (error) {
    if (error.status === 1) {
      return [];
    }
    throw error;
  }
}

export function updateRpcDigests(repository, { check = false } = {}) {
  const replacements = staleDigests(readFileSync(path.join(repository, RPC_SOURCE), "utf8"));
  if (replacements.size === 0 || check) {
    return replacements;
  }
  const stale = [...replacements.keys()];
  const files = trackedFilesContaining(repository, [...stale, ...stale.map(hex)]);
  for (const file of files) {
    const absolute = path.join(repository, file);
    const text = readFileSync(absolute, "utf8");
    const isSignedFixture = file.startsWith(FIXTURE_DIRECTORY) && file.endsWith(".json") &&
      Object.hasOwn(JSON.parse(text), "responseMacHex");
    writeFileSync(absolute, isSignedFixture ? rewriteFixture(file, text, replacements) : replaceAll(text, replacements));
  }
  const remaining = trackedFilesContaining(repository, [...stale, ...stale.map(hex)]);
  if (remaining.length !== 0) {
    throw new Error(`stale digests remain in ${remaining.join(", ")}`);
  }
  return replacements;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const check = process.argv.includes("--check");
  const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
  const replacements = updateRpcDigests(repository, { check });
  for (const [current, next] of replacements) {
    process.stdout.write(`${check ? "stale" : "updated"} ${current} -> ${next}\n`);
  }
  if (replacements.size === 0) {
    process.stdout.write("host RPC schema digests are current\n");
  }
  process.exitCode = check && replacements.size !== 0 ? 1 : 0;
}
