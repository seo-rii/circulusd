import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { deserialize, serialize } from "node:v8";
import vm from "node:vm";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const sourceRoot = process.env.CIRCULUSD_NATIVE_CELLD_SOURCE ?? path.join(repository, ".codex/native-storage-qualification/source");
const harnessPath = path.join(sourceRoot, "crates/celld/js/harness.js");
const harness = readFileSync(harnessPath, "utf8");
const scope = "GateCell:fixture";

function deferred() {
  let resolve, reject;
  const promise = new Promise((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

// Execute the complete production harness, rather than a copy of its dispatch
// code. These host-op fixtures expose the local transaction position and an
// independently controlled durability wait; they do not qualify a provider.
function fixture(initialPosition = 4) {
  const gateEntered = deferred(), gateReleased = deferred();
  const events = [], gates = [];
  let position = initialPosition, queued = false, transaction = false, frame;
  const sandbox = {
    ReadableStream, WritableStream, TransformStream, ReadableStreamBYOBReader,
    EventTarget, Event, AbortController, AbortSignal, Headers, URL, URLSearchParams,
    TextEncoder, TextDecoder, DOMException, queueMicrotask,
    __log: () => {},
    __als_get: () => frame,
    __als_set: (value) => { frame = value; },
    __do_id: () => "fixture",
    __sc_encode: (value) => new Uint8Array(serialize(value)),
    __sc_decode: (bytes) => deserialize(bytes),
    __writePosition: (target) => {
      assert.equal(target, scope);
      events.push(["position", position]);
      return position;
    },
    __gateWrite: async (target, through) => {
      assert.equal(target, scope);
      gates.push(through);
      events.push(["gate", through]);
      gateEntered.resolve();
      await gateReleased.promise;
      events.push(["durable", through]);
    },
    __storage_queue_put: (target) => { assert.equal(target, scope); queued = true; },
    __storage_flush_pending_puts: (target) => {
      assert.equal(target, scope);
      if (queued && !transaction) { position = (position ?? 0) + 1; queued = false; }
    },
    __storage_transaction_control: (target, operation) => {
      assert.equal(target, scope);
      if (operation === "start") transaction = true;
      else if (operation === "commit") {
        if (queued) position = (position ?? 0) + 1;
        queued = false;
        transaction = false;
        events.push(["commit", position]);
      } else if (operation.startsWith("rollback")) { queued = false; transaction = false; }
      else assert.fail(`unexpected transaction operation: ${operation}`);
    },
    __fixtureEvent: (event) => events.push([event]),
    __fixtureSerializationWrite: () => {
      position = (position ?? 0) + 1;
      events.push(["serialized", position]);
      return "serialized";
    },
    __rpc_call: async (target, name, method, bytes) => {
      assert.equal(target, scope); assert.equal(name, "name");
      events.push(["routed", method]);
      return sandbox.__dispatchRpc(target, method, bytes);
    },
  };
  vm.createContext(sandbox);
  vm.runInContext(harness, sandbox, { filename: harnessPath });
  vm.runInContext(`
    __cell.classes.GateCell = class extends __cf.DurableObject {
      async mutate(value) {
        await this.ctx.storage.transaction(async (storage) => {
          await storage.put("value", value);
        });
        __fixtureEvent("method-resolved");
        return { acknowledged: value };
      }
      read() { __fixtureEvent("method-resolved"); return { acknowledged: "read" }; }
      mutateDuringSerialization() {
        __fixtureEvent("method-resolved");
        return { get acknowledged() { return __fixtureSerializationWrite(); } };
      }
      mutateDuringJsonSerialization() {
        __fixtureEvent("method-resolved");
        return { toJSON() { return { acknowledged: __fixtureSerializationWrite() }; } };
      }
      async mutateThenThrow() {
        await this.mutate("failed");
        throw new Error("callee failed after commit");
      }
    };
    __cell.compat.jsRpc = true;
    __cell.namespaceKeys.GateCell = "fixture-namespace";
    __cell.owned[${JSON.stringify(scope)}] = true;
    globalThis.__fixtureStub = __cell.makeNamespace("GateCell").getByName("name");
  `, sandbox);
  return { sandbox, events, gates, gateEntered, gateReleased };
}

async function assertHeld(input, operation, position) {
  let observed = false;
  const response = operation().then(
    (value) => { observed = true; return value; },
    (error) => { observed = true; throw error; },
  );
  // Race the gate entry against the caller's actual settlement. The old
  // fast path resolves here and fails immediately instead of hanging.
  const reached = await Promise.race([
    input.gateEntered.promise.then(() => "gate"),
    response.then(() => "result", () => "error"),
  ]);
  assert.equal(reached, "gate", "the caller settled without entering the durability gate");
  await Promise.resolve();
  assert.equal(observed, false, "the caller observed a result before durability");
  assert.equal(input.events.some(([event]) => event === "method-resolved"), true);
  assert.deepEqual(input.gates, [position]);
  return { response, isObserved: () => observed };
}

test("owned RPC holds a completed transaction reply until its exact write position is durable", async () => {
  const input = fixture();
  const held = await assertHeld(input, () => input.sandbox.__fixtureStub.mutate("retained"), 5);
  assert.deepEqual(input.events.filter(([event]) => ["commit", "gate"].includes(event)), [["commit", 5], ["gate", 5]]);
  input.gateReleased.resolve();
  assert.deepEqual(await held.response, { acknowledged: "retained" });
});

test("byte and legacy JSON replies fail closed when the output gate rejects", async () => {
  for (const flavor of ["bytes", "json"]) {
    const input = fixture();
    const held = await assertHeld(input, () => flavor === "bytes"
      ? input.sandbox.__fixtureStub.mutate("not-acknowledged")
      : input.sandbox.__dispatchRpc(scope, "mutate", JSON.stringify(["not-acknowledged"]), true), 5);
    input.gateReleased.reject(new Error("native durability could not be proved"));
    await assert.rejects(held.response, /native durability could not be proved/);
    assert.equal(input.events.some(([event]) => event === "durable"), false);
  }
});

test("the gate samples after byte and legacy JSON result serialization", async () => {
  for (const flavor of ["bytes", "json"]) {
    const input = fixture();
    const held = await assertHeld(input, () => flavor === "bytes"
      ? input.sandbox.__fixtureStub.mutateDuringSerialization()
      : input.sandbox.__dispatchRpc(scope, "mutateDuringJsonSerialization", "[]", true), 5);
    assert.deepEqual(input.events.filter(([event]) => ["serialized", "gate"].includes(event)), [["serialized", 5], ["gate", 5]]);
    input.gateReleased.resolve();
    const reply = await held.response;
    assert.deepEqual(flavor === "json" ? JSON.parse(reply) : reply, { acknowledged: "serialized" });
  }
});

test("a newly opened connection's first transaction is gated through position one", async () => {
  const input = fixture(null);
  const held = await assertHeld(input, () => input.sandbox.__fixtureStub.mutate("fresh"), 1);
  input.gateReleased.resolve();
  assert.deepEqual(await held.response, { acknowledged: "fresh" });
});

test("owned read-only RPC still waits for the host's null-position ownership gate", async () => {
  const input = fixture();
  const held = await assertHeld(input, () => input.sandbox.__fixtureStub.read(), null);
  input.gateReleased.resolve();
  assert.deepEqual(await held.response, { acknowledged: "read" });
});

test("an encoded callee failure after a write cannot escape the gate", async () => {
  const input = fixture();
  const held = await assertHeld(input, () => input.sandbox.__fixtureStub.mutateThenThrow(), 5);
  input.gateReleased.reject(new Error("durability failure takes precedence"));
  await assert.rejects(held.response, /durability failure takes precedence/);
});

test("routed byte and JSON RPC retain host gating without a second inline wait", async () => {
  for (const flavor of ["bytes", "json"]) {
    const input = fixture();
    input.sandbox.__cell.owned[scope] = false;
    const reply = flavor === "bytes"
      ? await input.sandbox.__fixtureStub.mutate("routed")
      : JSON.parse(await input.sandbox.__dispatchRpc(scope, "mutate", '["routed"]'));
    assert.deepEqual(reply, { acknowledged: "routed" });
    assert.deepEqual(input.gates, []);
    assert.equal(input.events.some(([event]) => event === "commit"), true);
    assert.equal(input.events.some(([event]) => event === "routed"), flavor === "bytes");
  }
});
