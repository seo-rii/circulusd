import { describe, expect, it } from "vitest";

import {
  PI_EXECUTION_MAX_REQUEST_BYTES, PI_EXECUTION_PROTOCOL, sameExecutionBinding,
  snapshotExecutionBinding, snapshotExecutionReply, snapshotExecutionRequest, snapshotExecutionValue,
  type PiExecutionBinding, type PiExecutionRequest,
} from "../src/execution-rpc.ts";
import { PiGenesisGenerator } from "../src/genesis.ts";
import { environment, request, REVISION, SCOPE } from "./genesis-fixtures.ts";

const binding: PiExecutionBinding = { scope: { ...SCOPE }, runtimeRevisionDigest: REVISION,
  artifactDigest: `sha256:${"b".repeat(64)}` };
async function start(): Promise<PiExecutionRequest & { operation: "start" }> {
  const genesis = await (await PiGenesisGenerator.create(await environment())).createGenesis(await request());
  return { protocol: PI_EXECUTION_PROTOCOL, version: 1, binding: structuredClone(binding),
    turnId: genesis.checkpoint.turnId, executionId: "execution-wire-test", operation: "start", sequence: 0,
    authority: new Uint8Array([1, 2, 3]), checkpoint: genesis.checkpoint };
}

describe("bounded primitive Pi execution RPC", () => {
  it("accepts the actual genesis checkpoint and owns all caller bytes", async () => {
    const value = await start(), owned = snapshotExecutionRequest(value);
    expect(owned).toEqual(value);
    expect(owned.binding).not.toBe(value.binding);
    expect(Object.isFrozen(owned.binding.scope)).toBe(true);
    value.authority.fill(0);
    expect(owned.operation === "start" && Array.from(owned.authority)).toEqual([1, 2, 3]);
  });
  it("preserves finite raw Pi model/tool fractions without reinterpreting existing wrappers", async () => {
    const value = await start();
    const settlement = { outcome: { kind: "success", result: { value: 0.625, cost: 0.00001,
      existing: { "$pi.number.v1": "0.25" }, opaque: new Uint8Array([8, 9]) } } };
    const owned = snapshotExecutionRequest({ ...value, operation: "resume", settlement });
    settlement.outcome.result.opaque.fill(0); settlement.outcome.result.value = 99;
    expect(owned.operation === "resume" && owned.settlement).toEqual({ outcome: { kind: "success", result: {
      value: 0.625, cost: 0.00001, existing: { "$pi.number.v1": "0.25" }, opaque: new Uint8Array([8, 9]),
    } } });
  });
  it.each(["tenantId", "workspaceId", "actorSubjectId", "sessionId"] as const)("includes %s in the full scoped binding", (field) => {
    const owned = snapshotExecutionBinding(binding);
    expect(sameExecutionBinding(owned, { ...binding, scope: { ...SCOPE, [field]: "another-scoped-identity" } })).toBe(false);
  });
  it.each(["runtimeRevisionDigest", "artifactDigest"] as const)("pins %s independently", (field) => {
    expect(sameExecutionBinding(binding, { ...binding, [field]: `sha256:${"f".repeat(64)}` })).toBe(false);
  });
  it("rejects unbound checkpoints and malformed operation/sequence/version fields", async () => {
    const value = await start();
    for (const bad of [{ ...value, version: 2 }, { ...value, protocol: "other" }, { ...value, extra: true },
      { ...value, sequence: 1 }, { ...value, operation: "pull", sequence: 0 },
      { ...value, authority: new Uint8Array(0) }, { ...value, authority: new Uint8Array(4097) },
      { ...value, binding: { ...binding, runtimeRevisionDigest: `sha256:${"f".repeat(64)}` } },
      { ...value, binding: { ...binding, scope: { ...SCOPE, sessionId: "another-session" } } }]) {
      expect(() => snapshotExecutionRequest(bad)).toThrow("invalid or unavailable");
    }
  });
  it("never evaluates accessor properties or admits capabilities/custom prototypes", async () => {
    const value = await start();
    let invoked = false;
    Object.defineProperty(value, "authority", { enumerable: true, get() { invoked = true; return new Uint8Array([1]); } });
    expect(() => snapshotExecutionRequest(value)).toThrow("invalid or unavailable");
    expect(invoked).toBe(false);
    const shared = { value: 1 }, cycle: unknown[] = []; cycle.push(cycle);
    for (const bad of [() => undefined, new Date(), new Map(), Object.create({ capability: true }),
      [shared, shared], cycle, [undefined], Object.assign([], { extra: true }), new Uint8Array(new SharedArrayBuffer(1))]) {
      expect(() => snapshotExecutionValue(bad, 1024)).toThrow("invalid or unavailable");
    }
  });
  it("copies typed-array internal bytes without calling caller getters or iterators", () => {
    const bytes = new Uint8Array([3, 4]);
    const blocked = () => { throw new Error("caller-owned byte accessor must not run"); };
    Object.defineProperty(bytes, "buffer", { get: blocked });
    Object.defineProperty(bytes, "byteLength", { get: blocked });
    Object.defineProperty(bytes, Symbol.iterator, { get: blocked });
    expect(snapshotExecutionValue(bytes, 18)).toEqual(new Uint8Array([3, 4]));
  });
  it("bounds allocation, depth and UTF-8 strings and rejects nonfinite values", () => {
    expect(snapshotExecutionValue(new Uint8Array(8), 24)).toEqual(new Uint8Array(8));
    expect(() => snapshotExecutionValue(new Uint8Array(8), 23)).toThrow("invalid or unavailable");
    expect(snapshotExecutionValue("🙂", 36)).toBe("🙂");
    expect(() => snapshotExecutionValue("🙂", 35)).toThrow("invalid or unavailable");
    let deep: unknown = null;
    for (let count = 0; count < 65; count++) deep = [deep];
    for (const bad of [deep, NaN, Infinity, -Infinity, -0, "\ud800", new Uint8Array(PI_EXECUTION_MAX_REQUEST_BYTES)]) {
      expect(() => snapshotExecutionValue(bad, PI_EXECUTION_MAX_REQUEST_BYTES)).toThrow("invalid or unavailable");
    }
  });
  it("accepts one exact bounded response event and rejects arbitrary event/status shapes", async () => {
    const value = await start();
    const base = { protocol: value.protocol, version: value.version, binding: value.binding,
      turnId: value.turnId, executionId: value.executionId, operation: "pull", sequence: 1 };
    expect(snapshotExecutionReply({ ...base, status: "event", event: { type: "assistant_delta", delta: { text: "hello" } } }))
      .toEqual({ ...base, status: "event", event: { type: "assistant_delta", delta: { text: "hello" } } });
    for (const bad of [{ ...base, status: "opened" }, { ...base, status: "event", event: null },
      { ...base, status: "event", event: { type: "assistant_delta", delta: "x", authority: [1] } },
      { ...base, status: "event", event: { type: "unknown" } },
      { ...base, status: "event", event: { type: "checkpoint", checkpoint: value.checkpoint } },
      { ...base, status: "done", event: { type: "assistant_delta", delta: "x" } }]) {
      expect(() => snapshotExecutionReply(bad)).toThrow("invalid or unavailable");
    }
  });
});
