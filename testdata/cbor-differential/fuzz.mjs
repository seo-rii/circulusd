// Local differential test artifact. Node 24 imports the real TypeScript codec.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import fc from "fast-check";
import { decodeCanonicalCbor, encodeCanonicalCbor } from "../../packages/protocol-types/src/cbor.ts";
import { ProtocolValidationError } from "../../packages/protocol-types/src/errors.ts";

const root = fileURLToPath(new URL("../../", import.meta.url));
const { values: args } = parseArgs({
  options: {
    "go-probe": { type: "string" },
    artifacts: { type: "string" },
    case: { type: "string", default: "all" },
    seed: { type: "string", default: "20260905" },
    "num-runs": { type: "string", default: "1000" },
    path: { type: "string", default: "" },
    "time-limit-ms": { type: "string", default: "60000" },
  },
});

function integer(value, name, minimum, maximum) {
  const parsed = Number(value);
  assert(Number.isSafeInteger(parsed) && parsed >= minimum && parsed <= maximum,
    `${name} must be an integer from ${minimum} through ${maximum}`);
  return parsed;
}

const seed = integer(args.seed, "seed", -(2 ** 31), 2 ** 31 - 1);
const numRuns = integer(args["num-runs"], "num-runs", 1, 1_000_000);
const timeLimit = integer(args["time-limit-ms"], "time-limit-ms", 1, 3_600_000);
assert(["all", "value", "bytes"].includes(args.case), "case must be all, value, or bytes");
assert(!args.path || args.case !== "all", "--path requires a single --case");
const logs = join(homedir(), "logs");
mkdirSync(logs, { recursive: true, mode: 0o700 });
const artifacts = args.artifacts ? resolve(args.artifacts) : mkdtempSync(join(logs, "circulusd-cbor-differential-"));
mkdirSync(artifacts, { recursive: true, mode: 0o700 });
chmodSync(artifacts, 0o700);
const binary = args["go-probe"] ? resolve(args["go-probe"]) : join(artifacts, "cbor-probe");
if (!args["go-probe"]) {
  const build = spawnSync("go", ["build", "-o", binary, "./testdata/cbor-differential"],
    { cwd: root, encoding: "utf8", timeout: 120_000, maxBuffer: 1 << 20 });
  writeFileSync(join(artifacts, "build.log"), `${build.stdout ?? ""}${build.stderr ?? ""}`, { mode: 0o600 });
  assert.ifError(build.error);
  assert.equal(build.status, 0, `Go probe build failed; see ${join(artifacts, "build.log")}`);
}

const roomy = { maxBytes: 16384, maxDepth: 16, maxItems: 1024 };
const optionsArbitrary = fc.oneof(
  fc.constant(roomy),
  fc.record({ maxBytes: fc.integer({ min: 0, max: 256 }),
    maxDepth: fc.integer({ min: 0, max: 4 }), maxItems: fc.integer({ min: 0, max: 64 }) }),
);
const scalar = fc.oneof(
  fc.constantFrom("a", "b", "é", "e\u0301", "\ufeff", "한", "글", "😀", "\u0000"),
  fc.oneof(fc.integer({ min: 0, max: 0xd7ff }), fc.integer({ min: 0xe000, max: 0x10ffff }))
    .map((point) => String.fromCodePoint(point)),
);
const textArbitrary = fc.oneof(
  fc.constantFrom("", "__proto__", "constructor", "prototype", "toString", "\ufeff", "e\u0301", "é"),
  fc.array(scalar, { maxLength: 12 }).map((characters) => characters.join("")),
);
const leafArbitrary = fc.oneof(
  fc.constant({ kind: "null" }),
  fc.boolean().map((boolean) => ({ kind: "boolean", boolean })),
  fc.oneof(fc.maxSafeInteger(), fc.constantFrom(0, 23, 24, 255, 256, -1, -24, -256,
    Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER)).map((integer) => ({ kind: "integer", integer })),
  textArbitrary.map((text) => ({ kind: "text", text })),
  fc.uint8Array({ maxLength: 32 }).map((bytes) => ({ kind: "bytes", hex: Buffer.from(bytes).toString("hex") })),
);

function valueArbitrary(depth) {
  if (depth === 0) return leafArbitrary;
  const child = valueArbitrary(depth - 1);
  return fc.oneof(leafArbitrary,
    fc.array(child, { maxLength: 4 }).map((items) => ({ kind: "array", items })),
    fc.uniqueArray(fc.record({ key: textArbitrary, value: child }),
      { maxLength: 4, selector: (entry) => entry.key.normalize("NFC") })
      .map((entries) => ({ kind: "map", entries })),
  );
}

function materialize(value) {
  switch (value.kind) {
    case "null": return null;
    case "boolean": return value.boolean;
    case "integer": return value.integer;
    case "text": return value.text;
    case "bytes": return Uint8Array.from(Buffer.from(value.hex, "hex"));
    case "array": return value.items.map(materialize);
    case "map": return Object.fromEntries(value.entries.map((entry) => [entry.key, materialize(entry.value)]));
    default: throw new Error(`unknown wire kind ${value.kind}`);
  }
}

const values = valueArbitrary(3);
const mutatedBytes = fc.tuple(values, fc.integer({ min: 0, max: 3 }),
  fc.nat({ max: 4096 }), fc.integer({ min: 0, max: 255 })).map(([value, operation, offset, byte]) => {
  const encoded = encodeCanonicalCbor(materialize(value), roomy);
  const position = offset % encoded.length;
  if (operation === 0) {
    const changed = encoded.slice();
    changed[position] ^= byte || 1;
    return changed;
  }
  if (operation === 1) return encoded.slice(0, position);
  if (operation === 2) return Uint8Array.from([...encoded, byte]);
  return encoded;
});
const byteSeeds = [
  "", "f6", "f4", "00", "1818", "1b001fffffffffffff", "3b001ffffffffffffe",
  "63efbbbf", "6365cc81", "61ff", "1800", "f90000", "9fff", "c000", "0000",
  "a2616201616102", "a1616100", "80", "a0", "5bffffffffffffffff", "81f6",
];
const bytes = fc.oneof(fc.uint8Array({ maxLength: 256 }), mutatedBytes,
  fc.constantFrom(...byteSeeds).map((hex) => Uint8Array.from(Buffer.from(hex, "hex"))));

const child = spawn(binary, [], { cwd: root, stdio: ["pipe", "pipe", "inherit"] });
let pending;
let stopped;
const closed = new Promise((resolveClose) => {
  child.on("error", (error) => {
    stopped = error;
    pending?.reject(error);
  });
  child.on("close", (code, signal) => {
    stopped ??= new Error(`Go probe exited with code ${code}, signal ${signal}`);
    pending?.reject(stopped);
    resolveClose({ code, signal });
  });
});
child.stdin.on("error", (error) => {
  stopped = error;
  pending?.reject(error);
});
const lines = createInterface({ input: child.stdout });
lines.on("line", (line) => {
  if (!pending) {
    stopped = new Error("Go probe returned an unsolicited response");
    child.kill("SIGKILL");
    return;
  }
  try { pending.resolve(JSON.parse(line)); }
  catch (error) { pending.reject(error); }
});

async function probe(request) {
  if (stopped) throw stopped;
  return await new Promise((resolveResponse, rejectResponse) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      pending?.reject(new Error("Go probe exceeded its 5 second response deadline"));
    }, 5000);
    pending = {
      resolve(value) { clearTimeout(timer); pending = undefined; resolveResponse(value); },
      reject(error) { clearTimeout(timer); pending = undefined; rejectResponse(error); },
    };
    child.stdin.write(`${JSON.stringify(request)}\n`, (error) => { if (error) pending?.reject(error); });
  });
}

function typescriptResult(request) {
  let encoded;
  try {
    if (request.operation === "value") {
      encoded = encodeCanonicalCbor(materialize(request.value), request.options);
    } else {
      encoded = Uint8Array.from(Buffer.from(request.hex, "hex"));
      decodeCanonicalCbor(encoded, request.options);
    }
  } catch (error) {
    assert(error instanceof ProtocolValidationError, `unexpected TypeScript codec exception: ${String(error)}`);
    return { accepted: false, codecError: String(error) };
  }
  const decoded = decodeCanonicalCbor(encoded, request.options);
  const reencoded = encodeCanonicalCbor(decoded, request.options);
  assert.deepEqual(reencoded, encoded, "TypeScript accepted bytes changed after round trip");
  return { accepted: true, canonicalHex: Buffer.from(encoded).toString("hex") };
}

async function compare(request) {
  const go = await probe(request);
  assert.equal(go.requestError, undefined, `invalid Go test request: ${go.requestError}`);
  assert.equal(go.invariantError, undefined, `Go invariant: ${go.invariantError}`);
  const ts = typescriptResult(request);
  assert.equal(go.accepted, ts.accepted,
    `acceptance differs: Go ${JSON.stringify(go)}, TypeScript ${JSON.stringify(ts)}`);
  if (go.accepted) {
    assert.equal(go.canonicalHex, ts.canonicalHex, "Go and TypeScript canonical bytes differ");
  }
  return go.accepted;
}

const properties = {
  value: fc.asyncProperty(values, optionsArbitrary, async (value, options) => {
    const accepted = await compare({ operation: "value", value, options });
    if (options === roomy) assert(accepted, "generated bounded canonical value must be accepted");
  }),
  bytes: fc.asyncProperty(bytes, optionsArbitrary, async (encoded, options) => {
    await compare({ operation: "bytes", hex: Buffer.from(encoded).toString("hex"), options });
  }),
};

let failed = false;
let probeExit;
const results = [];
try {
  for (const name of args.case === "all" ? ["value", "bytes"] : [args.case]) {
    const details = await fc.check(properties[name], { seed, numRuns, path: args.path,
      interruptAfterTimeLimit: timeLimit, markInterruptAsFailure: true });
    const result = {
      property: name, seed: details.seed, path: details.counterexamplePath,
      numRuns: details.numRuns, numShrinks: details.numShrinks, failed: details.failed,
      interrupted: details.interrupted,
      counterexample: name === "bytes" && details.counterexample
        ? { hex: Buffer.from(details.counterexample[0]).toString("hex"), options: details.counterexample[1] }
        : details.counterexample,
      error: details.errorInstance ? String(details.errorInstance) : null,
    };
    results.push(result);
    writeFileSync(join(artifacts, `${name}.json`), `${JSON.stringify(result, null, 2)}\n`, { mode: 0o600 });
    console.log(JSON.stringify(result));
    failed ||= details.failed;
  }
} catch (error) {
  failed = true;
  results.push({ property: args.case, seed, path: args.path, error: String(error) });
  console.error(error);
} finally {
  child.stdin.end();
  const timer = setTimeout(() => child.kill("SIGKILL"), 1000);
  probeExit = await closed;
  clearTimeout(timer);
  lines.close();
}
failed ||= probeExit.code !== 0 || probeExit.signal !== null;
writeFileSync(join(artifacts, "status.json"),
  `${JSON.stringify({ exit_code: failed ? 1 : 0, probeExit, results }, null, 2)}\n`, { mode: 0o600 });
console.log(`Differential artifacts: ${artifacts}`);
process.exitCode = failed ? 1 : 0;
