import { describe, expect, it } from "vitest";
import { decodeCanonicalCbor, digestBytes, encodeCanonicalCbor } from "@circulusd/protocol-types";
import { EMPTY_DIGEST } from "../src/native-storage/codec.ts";
import { NativeStorageKernel } from "../src/native-storage/kernel.ts";
import { MAXIMUM_REVISION } from "../src/native-storage/types.ts";
import { NamespaceFixture, OBJECT_ID, StorageFixture, makeCommit, makeReceipt } from "./support/native-storage.ts";

function setup(bounds = {}) {
  const storage = new StorageFixture(), namespace = new NamespaceFixture();
  const kernel = new NativeStorageKernel(namespace.state(storage), namespace, bounds);
  return { storage, namespace, kernel };
}
async function current(kernel: NativeStorageKernel) {
  return (await kernel.readSnapshot({ objectId: OBJECT_ID })).snapshot;
}
describe("native storage transaction kernel", () => {
  it("creates a revision for every successful read-only callback and reopens exact bytes", async () => {
    const { storage, namespace, kernel } = setup();
    expect(await kernel.readSnapshot({ objectId: OBJECT_ID })).toEqual({
      snapshot: { objectId: OBJECT_ID, exists: false, revision: 0, stateDigest: EMPTY_DIGEST }, state: new Uint8Array(),
    });
    const first = await kernel.compareAndCommit(await makeCommit(await current(kernel), new Uint8Array(), [], false));
    expect(first.token.revision).toBe(1);
    const next = await kernel.compareAndCommit(await makeCommit(first.snapshot, new Uint8Array([4, 5])));
    expect(next.token.revision).toBe(2);
    const reopen = new NativeStorageKernel(namespace.state(storage), namespace);
    const snapshot = await reopen.readSnapshot({ objectId: OBJECT_ID });
    expect(snapshot.state).toEqual(new Uint8Array([4, 5]));
    expect(snapshot.snapshot.stateDigest).toBe(await digestBytes(snapshot.state));
    const noOp = await reopen.compareAndCommit(await makeCommit(snapshot.snapshot, new Uint8Array(), [], false));
    expect(noOp.token.revision).toBe(3);
    expect(noOp.snapshot.stateDigest).toBe(next.snapshot.stateDigest);
  });

  it("atomically persists full receipts and rejects changes to response or claims", async () => {
    const { kernel, storage } = setup();
    const receipt = await makeReceipt();
    const result = await kernel.compareAndCommit(await makeCommit(await current(kernel), new Uint8Array([2]), [{ commandId: "command", receipt }]));
    expect(await kernel.lookupReceipt({ snapshot: result.snapshot, commandId: "command" })).toEqual({
      snapshot: result.snapshot, commandId: "command", found: true, receipt,
    });
    for (const changed of [
      { ...receipt, response: new Uint8Array([99]) },
      { ...receipt, capabilityClaims: [{ kind: "model-dispatch", payload: new Uint8Array([10]) }] },
    ]) {
      const before = structuredClone(storage.values);
      await expect(kernel.compareAndCommit(await makeCommit(await current(kernel), new Uint8Array([7]), [
        { commandId: "a-new-command", receipt }, { commandId: "command", receipt: changed },
      ]))).rejects.toMatchObject({ code: "RECEIPT_CONFLICT" });
      expect(storage.values).toEqual(before);
    }
    const replay = await kernel.compareAndCommit(await makeCommit(await current(kernel), new Uint8Array(), [{ commandId: "command", receipt }], false));
    expect(replay.token.revision).toBe(2);
    expect((await kernel.lookupReceipt({ snapshot: replay.snapshot, commandId: "missing" })).receipt).toBeNull();
  });

  it("rolls back all state and receipt writes when the native transaction fails", async () => {
    const { kernel, storage } = setup();
    const receipt = await makeReceipt();
    const initial = await kernel.compareAndCommit(await makeCommit(await current(kernel), new Uint8Array([1])));
    const before = structuredClone(storage.values);
    storage.failPutAt = 3;
    await expect(kernel.compareAndCommit(await makeCommit(initial.snapshot, new Uint8Array([2]), [{ commandId: "new", receipt }]))).rejects.toThrow();
    expect(storage.values).toEqual(before);
    storage.failPutAt = 0;
    expect((await kernel.lookupReceipt({ snapshot: initial.snapshot, commandId: "new" })).found).toBe(false);
  });

  it("compares the complete snapshot before reads and writes and does not mutate conflicts", async () => {
    const { kernel, storage } = setup();
    const old = await current(kernel);
    const committed = await kernel.compareAndCommit(await makeCommit(old, new Uint8Array([1])));
    const mutations = storage.mutations;
    for (const ref of [old, { ...committed.snapshot, stateDigest: EMPTY_DIGEST }]) {
      await expect(kernel.lookupReceipt({ snapshot: ref, commandId: "x" })).rejects.toMatchObject({ code: "SNAPSHOT_CONFLICT" });
      await expect(kernel.compareAndCommit(await makeCommit(ref))).rejects.toMatchObject({ code: "SNAPSHOT_CONFLICT" });
    }
    expect(storage.mutations).toBe(mutations);
  });

  it("serializes competing CAS requests and allows exactly one commit", async () => {
    const { kernel } = setup();
    const snapshot = await current(kernel);
    const a = await makeCommit(snapshot, new Uint8Array([1])), b = await makeCommit(snapshot, new Uint8Array([2]));
    const results = await Promise.allSettled([kernel.compareAndCommit(a), kernel.compareAndCommit(b)]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")[0]).toMatchObject({ reason: { code: "SNAPSHOT_CONFLICT" } });
    expect((await current(kernel)).revision).toBe(1);
  });

  it("chunks state and receipts within native KV value limits and removes obsolete state chunks", async () => {
    const { storage, namespace, kernel } = setup();
    const state = new Uint8Array(3 * (1 << 20) + 1).fill(7);
    const receipt = await makeReceipt(new Uint8Array(2 * (1 << 20) + 11).fill(9));
    const result = await kernel.compareAndCommit(await makeCommit(await current(kernel), state, [{ commandId: "large", receipt }]));
    const reopened = new NativeStorageKernel(namespace.state(storage), namespace);
    const readState = (await reopened.readSnapshot({ objectId: OBJECT_ID })).state;
    expect(readState.byteLength).toBe(state.byteLength);
    expect(await digestBytes(readState)).toBe(await digestBytes(state));
    const stored = (await reopened.lookupReceipt({ snapshot: result.snapshot, commandId: "large" })).receipt!;
    expect(stored.response.byteLength).toBe(receipt.response.byteLength);
    expect(await digestBytes(stored.response)).toBe(await digestBytes(receipt.response));
    expect(stored.capabilityClaims).toEqual(receipt.capabilityClaims);
    await reopened.compareAndCommit(await makeCommit(result.snapshot, new Uint8Array([3])));
    expect(Array.from(storage.values.keys()).filter((key) => key.includes(".state."))).toHaveLength(1);
  });

  it("forces a fresh barrier mutation for repeated markers and older issued revisions", async () => {
    const { storage, namespace, kernel } = setup();
    const first = await kernel.compareAndCommit(await makeCommit(await current(kernel)));
    await kernel.compareAndCommit(await makeCommit(first.snapshot));
    const marker = new Uint8Array(32).fill(12), before = storage.mutations;
    expect(await kernel.confirmBarrier({ token: first.token, marker })).toEqual({ token: first.token, marker, observedRevision: 2, barrierSerial: 1 });
    const reopened = new NativeStorageKernel(namespace.state(storage), namespace);
    expect((await reopened.confirmBarrier({ token: first.token, marker })).barrierSerial).toBe(2);
    expect(storage.mutations).toBe(before + 2);
    expect((await current(kernel)).revision).toBe(2);
    await expect(kernel.confirmBarrier({ token: { ...first.token, revision: 3 }, marker })).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
  });

  it("rejects wrong physical routing before storage and copied anchors after reopening", async () => {
    const { storage, namespace, kernel } = setup();
    await expect(kernel.readSnapshot({ objectId: "other" })).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
    expect(storage.calls).toBe(0);
    await kernel.compareAndCommit(await makeCommit(await current(kernel)));
    const relabeled = new NativeStorageKernel(namespace.state(storage, "other"), namespace);
    await expect(relabeled.readSnapshot({ objectId: "other" })).rejects.toMatchObject({ code: "CORRUPT_STATE" });
  });

  it("rejects corrupt chunks and receipt manifests without new mutations", async () => {
    const { storage, kernel } = setup();
    const receipt = await makeReceipt();
    const result = await kernel.compareAndCommit(await makeCommit(await current(kernel), new Uint8Array([1]), [{ commandId: "receipt", receipt }]));
    const stateKey = Array.from(storage.values.keys()).find((key) => key.includes(".state."))!;
    storage.values.set(stateKey, new Uint8Array([9]));
    const before = storage.mutations;
    await expect(kernel.readSnapshot({ objectId: OBJECT_ID })).rejects.toMatchObject({ code: "CORRUPT_STATE" });
    await expect(kernel.compareAndCommit(await makeCommit(result.snapshot))).rejects.toMatchObject({ code: "CORRUPT_STATE" });
    expect(storage.mutations).toBe(before);
    storage.values.set(stateKey, new Uint8Array([1]));
    const manifest = Array.from(storage.values.keys()).find((key) => key.endsWith(".manifest"))!;
    storage.values.set(manifest, new Uint8Array([0xff]));
    await expect(kernel.lookupReceipt({ snapshot: result.snapshot, commandId: "receipt" })).rejects.toMatchObject({ code: "CORRUPT_STATE" });
  });

  it.each(["orphan", "copied"] as const)("rejects %s receipt lookup and exact replay commit without an object anchor", async (shape) => {
    const original = setup(), receipt = await makeReceipt();
    await original.kernel.compareAndCommit(await makeCommit(await current(original.kernel), new Uint8Array(), [{ commandId: "receipt", receipt }]));
    const target = shape === "orphan" ? original.storage : new StorageFixture();
    if (shape === "orphan") target.values.delete("circulusd.native-storage.v1.metadata");
    else {
      for (const [key, value] of original.storage.values) if (key.includes(".receipt.")) target.values.set(key, structuredClone(value));
    }
    const objectId = shape === "orphan" ? OBJECT_ID : "other-object";
    const kernel = new NativeStorageKernel(original.namespace.state(target, objectId), original.namespace);
    const snapshot = (await kernel.readSnapshot({ objectId })).snapshot;
    expect(snapshot.exists).toBe(false);
    const before = structuredClone(target.values), mutations = target.mutations;
    await expect(kernel.lookupReceipt({ snapshot, commandId: "receipt" })).rejects.toMatchObject({ code: "CORRUPT_STATE" });
    await expect(kernel.compareAndCommit(await makeCommit(snapshot, new Uint8Array(), [{ commandId: "receipt", receipt }], false))).rejects.toMatchObject({ code: "CORRUPT_STATE" });
    expect(target.values).toEqual(before); expect(target.mutations).toBe(mutations);
  });

  it("validates digest, sorted full writes and measured lower bounds before storage", async () => {
    const { kernel, storage } = setup({ maxStateBytes: 2, maxReceiptResponseBytes: 2, maxCapabilityClaimBytes: 2, maxReceiptWrites: 1 });
    const empty = { objectId: OBJECT_ID, exists: false, revision: 0, stateDigest: EMPTY_DIGEST };
    const good = await makeCommit(empty, new Uint8Array([1]));
    for (const input of [
      { ...good, requestDigest: EMPTY_DIGEST },
      await makeCommit(empty, new Uint8Array([1, 2, 3])),
      await makeCommit(empty, new Uint8Array(), [{ commandId: "x", receipt: await makeReceipt(new Uint8Array([1, 2, 3])) }]),
      await makeCommit(empty, new Uint8Array(), [{ commandId: "x", receipt: { ...(await makeReceipt()), capabilityClaims: [
        { kind: "a", payload: new Uint8Array([1, 2]) }, { kind: "b", payload: new Uint8Array([3]) },
      ] } }]),
    ]) await expect(kernel.compareAndCommit(input)).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
    expect(storage.calls).toBe(0);
  });

  it("rejects accessor fields before evaluating them or reading native storage", async () => {
    const { kernel, storage } = setup();
    let invoked = false;
    const input = Object.defineProperty({}, "objectId", { enumerable: true, get: () => { invoked = true; return OBJECT_ID; } });
    await expect(kernel.readSnapshot(input)).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
    expect(invoked).toBe(false); expect(storage.calls).toBe(0);
  });

  it("uses UTF-8 receipt ordering and rejects descending supplementary IDs", async () => {
    const { kernel } = setup();
    const snapshot = await current(kernel), receipt = await makeReceipt();
    const sorted = [{ commandId: "\ue000", receipt }, { commandId: "😀", receipt: structuredClone(receipt) }];
    const result = await kernel.compareAndCommit(await makeCommit(snapshot, new Uint8Array(), sorted));
    await expect(kernel.compareAndCommit(await makeCommit(result.snapshot, new Uint8Array(), [...sorted].reverse()))).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
  });

  it("fails closed on revision and barrier counter exhaustion", async () => {
    const { kernel, storage } = setup();
    await kernel.compareAndCommit(await makeCommit(await current(kernel)));
    const key = "circulusd.native-storage.v1.metadata";
    const metadata = decodeCanonicalCbor(storage.values.get(key) as Uint8Array) as Record<string, unknown>;
    storage.values.set(key, encodeCanonicalCbor({ ...metadata, revision: MAXIMUM_REVISION }));
    const maximum = await current(kernel);
    // Build this request without CommitDigest: the parser rejects revision
    // exhaustion before external storage or any generation is possible.
    await expect(kernel.compareAndCommit({ snapshot: maximum, stateWritten: false, state: new Uint8Array(), receipts: [], requestDigest: EMPTY_DIGEST })).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
    storage.values.set(key, encodeCanonicalCbor({ ...metadata, barrierSerial: MAXIMUM_REVISION, barrierMarker: new Uint8Array(32) }));
    await expect(kernel.confirmBarrier({ token: { objectId: OBJECT_ID, revision: 1 }, marker: new Uint8Array(32) })).rejects.toMatchObject({ code: "UNAVAILABLE" });
  });
});
