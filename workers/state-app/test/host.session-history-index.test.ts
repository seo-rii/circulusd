import { describe, expect, it } from "vitest";
import { decodeCanonicalCbor, digestBytes, encodeCanonicalCbor, type Digest } from "@circulusd/protocol-types";
import {
  SessionHistoryIndex, emptySessionHistoryIndexRoot, type SessionHistoryIndexRoot,
} from "../src/host/session-history-index.ts";
import { RestartableDurableStorage } from "./support/restartable-durable-storage.ts";

const ANCHOR = "test-history-root";
const PREFIX = "circulusd.state-app.session-history.v1.index.";
const value = (n: number): Digest => `sha256:${n.toString(16).padStart(64, "0")}`;

async function insert(storage: RestartableDurableStorage, entries: readonly [string, Digest][]) {
  return storage.transaction(async (transaction) => {
    const root = await transaction.get<SessionHistoryIndexRoot>(ANCHOR) ?? emptySessionHistoryIndexRoot();
    const index = new SessionHistoryIndex(transaction, root);
    for (const [key, digest] of entries) await index.set(key, digest);
    const writes = index.pendingWrites();
    expect(new Set(writes.map((write) => write.key)).size).toBe(writes.length);
    // This batch's exact write-set is checked before any physical mutation.
    expect(writes.length + 1).toBeLessThanOrEqual(128);
    await index.flush();
    await transaction.put(ANCHOR, index.root());
    return index.root();
  });
}

describe("authenticated Session history index", () => {
  it("survives splits, replacement, restart and proves absence without a growing root", async () => {
    let storage = new RestartableDurableStorage();
    const expected = new Map<string, Digest>();
    let root = emptySessionHistoryIndexRoot();
    // More than degree^2 entries forces internal as well as leaf splits.
    for (let batch = 0; batch < 32; batch += 1) {
      const entries: [string, Digest][] = [];
      for (let offset = 0; offset < 32; offset += 1) {
        const n = (batch * 32 + offset) * 593 % 1024;
        const key = `${n % 2 === 0 ? "command" : "admission"}:identity-${n}`;
        entries.push([key, value(n)]);
        expected.set(key, value(n));
      }
      root = await insert(storage, entries);
      storage = storage.restart();
    }
    expect(root.size).toBe(1024);
    expect(encodeCanonicalCbor(root).byteLength).toBeLessThan(160);
    const allocated = root.nextNodeId;
    root = await insert(storage, [["command:identity-0", value(2000)]]);
    expected.set("command:identity-0", value(2000));
    expect(root.size).toBe(1024);
    expect(root.nextNodeId).toBe(allocated);
    await storage.transaction(async (transaction) => {
      const index = new SessionHistoryIndex(transaction, root);
      for (const [key, digest] of expected) expect(await index.get(key)).toBe(digest);
      expect(await index.get("command:never-used")).toBeNull();
      expect(await index.get("turn:identity-0")).toBeNull();
      const before = index.root();
      await index.set("command:identity-0", value(2000));
      expect(index.pendingWrites()).toEqual([]);
      expect(index.root()).toEqual(before);
    });
    // Every allocated page stays reachable: standard in-place B-tree splits
    // create no abandoned ancestor versions requiring unbounded GC metadata.
    await storage.transaction(async (transaction) => {
      const seen = new Set<number>();
      const pending = [root.root!];
      while (pending.length > 0) {
        const ref = pending.pop()!;
        expect(seen.has(ref.nodeId)).toBe(false);
        seen.add(ref.nodeId);
        const bytes = await transaction.get<Uint8Array>(`${PREFIX}${ref.nodeId}`);
        expect(bytes).toBeDefined();
        expect(await digestBytes(bytes!)).toBe(ref.digest);
        const node = decodeCanonicalCbor(bytes!) as { children: typeof pending };
        pending.push(...node.children);
      }
      expect(seen.size).toBe(root.nextNodeId - 1);
      expect(storage.durableEntryCount).toBe(seen.size + 1);
    });
  }, 30_000);

  it.each(["root", "children"] as const)("rejects missing %s pages even for a lookup that would otherwise be absent", async (missing) => {
    const storage = new RestartableDurableStorage();
    const root = await insert(storage, Array.from({ length: 40 }, (_, n) => [`command:${n}`, value(n)]));
    await storage.transaction(async (transaction) => {
      if (missing === "root") await transaction.delete(`${PREFIX}${root.root!.nodeId}`);
      else {
        const bytes = await transaction.get<Uint8Array>(`${PREFIX}${root.root!.nodeId}`);
        const node = decodeCanonicalCbor(bytes!) as { children: { nodeId: number }[] };
        expect(node.children.length).toBeGreaterThan(1);
        for (const child of node.children) await transaction.delete(`${PREFIX}${child.nodeId}`);
      }
    });
    await expect(storage.transaction(async (transaction) => {
      const index = new SessionHistoryIndex(transaction, root);
      await index.get("command:never-used");
    })).rejects.toMatchObject({ code: "CORRUPT_STATE" });
  });

  it("rejects modified bytes and does not let a caught failure flush cached changes", async () => {
    const storage = new RestartableDurableStorage();
    const root = await insert(storage, [["command:one", value(1)]]);
    await storage.transaction(async (transaction) => {
      const key = `${PREFIX}${root.root!.nodeId}`;
      const bytes = await transaction.get<Uint8Array>(key);
      bytes![bytes!.length - 1] ^= 1;
      await transaction.put(key, bytes);
    });
    const revision = storage.durableRevision;
    await storage.transaction(async (transaction) => {
      const index = new SessionHistoryIndex(transaction, root);
      await expect(index.get("command:one")).rejects.toMatchObject({ code: "CORRUPT_STATE" });
      await expect(index.set("command:two", value(2))).rejects.toMatchObject({ code: "CORRUPT_STATE" });
      await expect(index.flush()).rejects.toMatchObject({ code: "CORRUPT_STATE" });
      expect(() => index.root()).toThrow();
    });
    expect(storage.durableRevision).toBe(revision);
  });

  it.each(["before-commit", "after-commit-before-result"] as const)("keeps pages and their root atomic across %s", async (phase) => {
    let storage = new RestartableDurableStorage();
    await insert(storage, Array.from({ length: 31 }, (_, n) => [`command:${n}`, value(n)]));
    storage.injectCrashOnce(phase);
    await expect(insert(storage, [["command:split", value(999)]])).rejects.toMatchObject({ phase });
    storage = storage.restart();
    await storage.transaction(async (transaction) => {
      const root = await transaction.get<SessionHistoryIndexRoot>(ANCHOR);
      const index = new SessionHistoryIndex(transaction, root!);
      for (let n = 0; n < 31; n += 1) expect(await index.get(`command:${n}`)).toBe(value(n));
      expect(await index.get("command:split")).toBe(phase === "before-commit" ? null : value(999));
      expect(root!.size).toBe(phase === "before-commit" ? 31 : 32);
    });
  });

  it("stages independent snapshots and rejects malformed anchors", async () => {
    const storage = new RestartableDurableStorage();
    await storage.transaction(async (transaction) => {
      const input = emptySessionHistoryIndexRoot();
      const index = new SessionHistoryIndex(transaction, input);
      await index.set("command:one", value(1));
      expect(input).toEqual(emptySessionHistoryIndexRoot());
      const root = index.root();
      const writes = index.pendingWrites();
      root.size = 99;
      writes[0]!.value.fill(0);
      expect(await transaction.get(writes[0]!.key)).toBeUndefined();
      await index.flush();
      const restored = new SessionHistoryIndex(transaction, index.root());
      expect(await restored.get("command:one")).toBe(value(1));
      for (const invalid of [
        { ...input, size: 1 }, { ...input, nextNodeId: 2 },
        { ...index.root(), root: { nodeId: 1, digest: "invalid" } },
        { ...index.root(), extra: true },
      ]) expect(() => new SessionHistoryIndex(transaction, invalid as SessionHistoryIndexRoot))
        .toThrowError(/invalid root anchor/);
    });
  });
});
