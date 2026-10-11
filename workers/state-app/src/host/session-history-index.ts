import {
  decodeCanonicalCbor, digestBytes, encodeCanonicalCbor, isDigest, type Digest,
} from "@circulusd/protocol-types";
import { HostContractError, type TransactionPort } from "./contracts.ts";

const DEGREE = 16;
const MAX_KEYS = 2 * DEGREE - 1;
const MAX_DEPTH = 14;
const MAX_NODE_BYTES = 16 * 1024;
const PREFIX = "circulusd.state-app.session-history.v1.index.";
const encoder = new TextEncoder();

interface NodePointer { nodeId: number; digest: Digest }
export interface SessionHistoryIndexRoot {
  version: 1;
  root: NodePointer | null;
  nextNodeId: number;
  size: number;
}
interface IndexNode {
  version: 1;
  nodeId: number;
  leaf: boolean;
  keys: string[];
  values: Digest[];
  children: NodePointer[];
}
interface CachedNode { node: IndexNode; pointer: NodePointer; bytes: Uint8Array }
export interface SessionHistoryIndexWrite { readonly key: string; readonly value: Uint8Array }

function corrupt(message: string): never {
  throw new HostContractError("CORRUPT_STATE", `Session history index: ${message}`);
}
function exact(value: unknown, fields: readonly string[]): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    !(value instanceof Uint8Array) && Object.keys(value).length === fields.length &&
    fields.every((field) => Object.hasOwn(value, field));
}
function natural(value: unknown, minimum: number): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= minimum;
}
function pointer(value: unknown, nextNodeId: number): value is NodePointer {
  return exact(value, ["nodeId", "digest"]) && natural(value.nodeId, 1) &&
    value.nodeId < nextNodeId && isDigest(value.digest);
}

export function emptySessionHistoryIndexRoot(): SessionHistoryIndexRoot {
  return { version: 1, root: null, nextNodeId: 1, size: 0 };
}

export function validateSessionHistoryIndexRoot(value: unknown): SessionHistoryIndexRoot {
  if (!exact(value, ["version", "root", "nextNodeId", "size"]) || value.version !== 1 ||
    !natural(value.size, 0) || !natural(value.nextNodeId, 1) ||
    (value.root === null
      ? value.size !== 0 || value.nextNodeId !== 1
      : value.size === 0 || !pointer(value.root, value.nextNodeId))) {
    corrupt("invalid root anchor");
  }
  return structuredClone(value) as unknown as SessionHistoryIndexRoot;
}

/**
 * Transaction-local authenticated B-tree. A missing page is corruption, whereas
 * absence from a verified leaf proves that an ID has never been indexed.
 * Splits retain the left node's ID and allocate only reachable right/parent
 * nodes. Thus insertion creates no unreachable historical index pages.
 * Nothing is written until flush; callers include pendingWrites in their exact
 * transaction budget together with archive rows, blob ownership and hot state.
 */
export class SessionHistoryIndex {
  readonly #transaction: Pick<TransactionPort, "get" | "put">;
  readonly #anchor: SessionHistoryIndexRoot;
  readonly #cache = new Map<number, CachedNode>();
  readonly #dirty = new Set<number>();
  #failed = false;

  constructor(transaction: Pick<TransactionPort, "get" | "put">, root: SessionHistoryIndexRoot) {
    this.#transaction = transaction;
    this.#anchor = validateSessionHistoryIndexRoot(root);
  }

  root(): SessionHistoryIndexRoot {
    this.#assertHealthy();
    return structuredClone(this.#anchor);
  }

  pendingWrites(): readonly SessionHistoryIndexWrite[] {
    this.#assertHealthy();
    return [...this.#dirty].sort((a, b) => a - b).map((id) => ({
      key: `${PREFIX}${id}`, value: new Uint8Array(this.#cache.get(id)!.bytes),
    }));
  }

  async flush(): Promise<void> {
    this.#assertHealthy();
    try {
      for (const { key, value } of this.pendingWrites()) await this.#transaction.put(key, value);
      this.#dirty.clear();
    } catch (error) {
      this.#failed = true;
      throw error;
    }
  }

  async get(key: string): Promise<Digest | null> {
    this.#assertHealthy();
    try {
      return await this.#find(await this.#key(key));
    } catch (error) {
      this.#failed = true;
      throw error;
    }
  }

  async set(key: string, value: Digest): Promise<void> {
    this.#assertHealthy();
    if (!isDigest(value)) throw new TypeError("Session history index values must be digests");
    try {
      const hashed = await this.#key(key);
      const previous = await this.#find(hashed);
      if (previous === value) return;
      if (previous !== null) {
        this.#anchor.root = await this.#replace(this.#anchor.root!, hashed, value);
        return;
      }
      if (this.#anchor.size === Number.MAX_SAFE_INTEGER) corrupt("entry count exhausted");
      if (this.#anchor.root === null) {
        const node = this.#allocate(true);
        node.keys.push(hashed);
        node.values.push(value);
        this.#anchor.root = await this.#save(node);
      } else {
        const current = await this.#load(this.#anchor.root);
        if (current.keys.length === MAX_KEYS) {
          const parent = this.#allocate(false);
          parent.children.push(this.#anchor.root);
          await this.#split(parent, 0, current);
          this.#anchor.root = await this.#save(parent);
        }
        this.#anchor.root = await this.#insert(this.#anchor.root, hashed, value, 0);
      }
      this.#anchor.size += 1;
    } catch (error) {
      // A failed staged insertion must never be flushed or reused by a caller
      // that catches the error. Its surrounding storage transaction must abort.
      this.#failed = true;
      throw error;
    }
  }

  #assertHealthy(): void {
    if (this.#failed) corrupt("a failed index operation requires transaction rollback");
  }

  async #key(key: string): Promise<string> {
    if (typeof key !== "string" || key.length === 0 || key.normalize("NFC") !== key ||
      encoder.encode(key).byteLength > 4096) throw new TypeError("invalid Session history index key");
    return (await digestBytes(encoder.encode(`circulusd.session-history.index-key.v1\0${key}`))).slice(7);
  }

  async #load(ref: NodePointer): Promise<IndexNode> {
    if (!pointer(ref, this.#anchor.nextNodeId)) corrupt("invalid node pointer");
    const cached = this.#cache.get(ref.nodeId);
    if (cached !== undefined) {
      if (cached.pointer.digest !== ref.digest) corrupt("inconsistent node digest");
      return cached.node;
    }
    const stored = await this.#transaction.get<unknown>(`${PREFIX}${ref.nodeId}`);
    if (!(stored instanceof Uint8Array) || stored.byteLength === 0 || stored.byteLength > MAX_NODE_BYTES) {
      corrupt("referenced page is missing or oversized");
    }
    const bytes = new Uint8Array(stored);
    if (await digestBytes(bytes) !== ref.digest) corrupt("page digest mismatch");
    let decoded: unknown;
    try { decoded = decodeCanonicalCbor(bytes, { maxBytes: MAX_NODE_BYTES, maxDepth: 8, maxItems: 512 }); }
    catch { corrupt("invalid canonical page"); }
    if (!exact(decoded, ["version", "nodeId", "leaf", "keys", "values", "children"]) ||
      decoded.version !== 1 || decoded.nodeId !== ref.nodeId || typeof decoded.leaf !== "boolean" ||
      !Array.isArray(decoded.keys) || !Array.isArray(decoded.values) || !Array.isArray(decoded.children) ||
      decoded.keys.length === 0 || decoded.keys.length > MAX_KEYS ||
      decoded.values.length !== decoded.keys.length ||
      decoded.children.length !== (decoded.leaf ? 0 : decoded.keys.length + 1) ||
      decoded.keys.some((key, index, keys) => typeof key !== "string" || !/^[0-9a-f]{64}$/.test(key) ||
        (index > 0 && keys[index - 1] >= key)) ||
      decoded.values.some((value) => !isDigest(value)) ||
      decoded.children.some((child) => !pointer(child, this.#anchor.nextNodeId) || child.nodeId === ref.nodeId) ||
      new Set(decoded.children.map((child) => child.nodeId)).size !== decoded.children.length) {
      corrupt("invalid page shape or ordering");
    }
    const node = decoded as unknown as IndexNode;
    this.#cache.set(ref.nodeId, { node, pointer: structuredClone(ref), bytes });
    return node;
  }

  #allocate(leaf: boolean): IndexNode {
    if (this.#anchor.nextNodeId === Number.MAX_SAFE_INTEGER) corrupt("node identity exhausted");
    return { version: 1, nodeId: this.#anchor.nextNodeId++, leaf, keys: [], values: [], children: [] };
  }

  async #save(node: IndexNode): Promise<NodePointer> {
    const bytes = encodeCanonicalCbor(node, { maxBytes: MAX_NODE_BYTES, maxDepth: 8, maxItems: 512 });
    const ref = { nodeId: node.nodeId, digest: await digestBytes(bytes) };
    this.#cache.set(node.nodeId, { node, pointer: ref, bytes });
    this.#dirty.add(node.nodeId);
    return structuredClone(ref);
  }

  async #find(key: string): Promise<Digest | null> {
    let ref = this.#anchor.root;
    let lower: string | undefined;
    let upper: string | undefined;
    let depth = 0;
    const visited = new Set<number>();
    while (ref !== null) {
      if (depth++ >= MAX_DEPTH || visited.has(ref.nodeId)) corrupt("index path is cyclic or too deep");
      visited.add(ref.nodeId);
      const node = await this.#load(ref);
      if ((lower !== undefined && node.keys[0]! <= lower) ||
        (upper !== undefined && node.keys.at(-1)! >= upper) ||
        (depth > 1 && node.keys.length < DEGREE - 1)) corrupt("page violates its parent bounds");
      let i = 0;
      while (i < node.keys.length && node.keys[i]! < key) i += 1;
      if (node.keys[i] === key) return node.values[i]!;
      if (node.leaf) return null;
      lower = i === 0 ? lower : node.keys[i - 1];
      upper = i === node.keys.length ? upper : node.keys[i];
      ref = node.children[i]!;
    }
    return null;
  }

  async #replace(ref: NodePointer, key: string, value: Digest): Promise<NodePointer> {
    const node = await this.#load(ref);
    let i = 0;
    while (i < node.keys.length && node.keys[i]! < key) i += 1;
    if (node.keys[i] === key) node.values[i] = value;
    else {
      if (node.leaf) corrupt("replacement lost its verified key");
      node.children[i] = await this.#replace(node.children[i]!, key, value);
    }
    return this.#save(node);
  }

  async #split(parent: IndexNode, position: number, child: IndexNode): Promise<void> {
    const right = this.#allocate(child.leaf);
    const medianKey = child.keys[DEGREE - 1]!;
    const medianValue = child.values[DEGREE - 1]!;
    right.keys = child.keys.splice(DEGREE);
    right.values = child.values.splice(DEGREE);
    child.keys.pop();
    child.values.pop();
    if (!child.leaf) right.children = child.children.splice(DEGREE);
    const leftRef = await this.#save(child);
    const rightRef = await this.#save(right);
    parent.keys.splice(position, 0, medianKey);
    parent.values.splice(position, 0, medianValue);
    parent.children.splice(position, 1, leftRef, rightRef);
  }

  async #insert(ref: NodePointer, key: string, value: Digest, depth: number): Promise<NodePointer> {
    if (depth >= MAX_DEPTH) corrupt("index depth exhausted");
    const node = await this.#load(ref);
    let i = 0;
    while (i < node.keys.length && node.keys[i]! < key) i += 1;
    if (node.leaf) {
      node.keys.splice(i, 0, key);
      node.values.splice(i, 0, value);
    } else {
      const child = await this.#load(node.children[i]!);
      if (child.keys.length === MAX_KEYS) {
        await this.#split(node, i, child);
        if (node.keys[i]! < key) i += 1;
      }
      node.children[i] = await this.#insert(node.children[i]!, key, value, depth + 1);
    }
    return this.#save(node);
  }
}
