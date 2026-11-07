import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { appendFileSync, cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { SCHEMA_SOURCE_FILES } from "../../workers/state-app/scripts/generate-rpc-digests.mjs";
import { responseMac, rewriteFixture, staleDigests } from "../../workers/state-app/scripts/update-rpc-digests.mjs";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const fixtureDirectory = path.join(repository, "packages/protocol-types/fixtures");
const rpcSource = "workers/state-app/src/host/rpc.ts";
const scripts = ["workers/state-app/scripts/generate-rpc-digests.mjs", "workers/state-app/scripts/update-rpc-digests.mjs"];

function signedFixtures() {
  return readdirSync(fixtureDirectory)
    .filter((name) => name.endsWith(".json"))
    .map((name) => [name, readFileSync(path.join(fixtureDirectory, name), "utf8")])
    .filter(([, text]) => Object.hasOwn(JSON.parse(text), "responseMacHex"));
}

function pinnedDigests() {
  const source = readFileSync(path.join(repository, rpcSource), "utf8");
  return [...source.matchAll(/schemaDigest:\s*"(sha256:[0-9a-f]{64})"/g)].map(([, digest]) => digest);
}

test("the response MAC formula reproduces every committed signed fixture", () => {
  const fixtures = signedFixtures();
  assert.ok(fixtures.length >= 5);
  for (const [name, text] of fixtures) {
    const fixture = JSON.parse(text);
    assert.equal(responseMac(fixture), fixture.responseMacHex, name);
  }
});

test("committed host RPC schema digests are current", () => {
  assert.equal(staleDigests(readFileSync(path.join(repository, rpcSource), "utf8")).size, 0);
});

test("a fixture whose request bytes carry a replaced digest is refused", () => {
  const [name, text] = signedFixtures().find(([, candidate]) => {
    const fixture = JSON.parse(candidate);
    return fixture.requestCborHex.includes(Buffer.from(fixture.schemaDigest, "utf8").toString("hex"));
  });
  const fixture = JSON.parse(text);
  const replacements = new Map([[fixture.schemaDigest, `sha256:${"0".repeat(64)}`]]);
  assert.throws(() => rewriteFixture(name, text, replacements), /request bytes carry a stale digest/);
});

test("a schema source change updates every pinned copy and re-signs fixture responses", (t) => {
  const directory = mkdtempSync(path.join(tmpdir(), "circulusd-rpc-digests-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const testModule = path.join(repository, "workers/state-app/test/host.rpc.test.ts");
  const sources = SCHEMA_SOURCE_FILES.map((relative) =>
    path.relative(repository, path.resolve(path.dirname(testModule), relative)));
  const pinnedCopies = execFileSync("git", ["grep", "-l", "-F", ...pinnedDigests().flatMap((digest) => ["-e", digest])], {
    cwd: repository,
    encoding: "utf8",
  }).split("\n").filter(Boolean);
  for (const file of new Set([...sources, ...scripts, rpcSource, ...pinnedCopies])) {
    mkdirSync(path.dirname(path.join(directory, file)), { recursive: true });
    cpSync(path.join(repository, file), path.join(directory, file));
  }
  execFileSync("git", ["init", "-q"], { cwd: directory });
  execFileSync("git", ["add", "-A"], { cwd: directory });
  const update = (...flags) => spawnSync(process.execPath, [path.join(directory, scripts[1]), ...flags], {
    cwd: directory,
    encoding: "utf8",
  });

  appendFileSync(path.join(directory, "packages/protocol-types/src/errors.ts"), "// schema change\n");
  assert.equal(update("--check").status, 1);
  const updated = update();
  assert.equal(updated.status, 0, updated.stderr);
  assert.equal(update("--check").status, 0);

  const before = pinnedDigests();
  const leftover = spawnSync("git", ["grep", "-l", "-F", ...before.flatMap((digest) => ["-e", digest])], {
    cwd: directory,
    encoding: "utf8",
  });
  assert.equal(leftover.status, 1, `stale digests remain in ${leftover.stdout}`);
  for (const file of pinnedCopies.filter((candidate) => candidate.startsWith("packages/protocol-types/fixtures/"))) {
    const fixture = JSON.parse(readFileSync(path.join(directory, file), "utf8"));
    if (Object.hasOwn(fixture, "responseMacHex")) {
      assert.equal(responseMac(fixture), fixture.responseMacHex, file);
    }
  }
});
