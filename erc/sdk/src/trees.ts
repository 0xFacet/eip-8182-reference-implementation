// Merkle trees per spec §15.4: internal nodes poseidon(left, right), LSB-first
// paths, EMPTY[0]=0, EMPTY[h+1]=poseidon(EMPTY[h],EMPTY[h]).

import { poseidon } from "./poseidon2.ts";
import { type FieldNumberish, toField } from "./field.ts";

const emptyLadderCache = new Map<number, bigint[]>();

/** EMPTY[0..depth] ladder (length depth+1). */
export function emptyLadder(depth: number): bigint[] {
  const cached = emptyLadderCache.get(depth);
  if (cached) return cached;
  const ladder: bigint[] = [0n];
  for (let h = 0; h < depth; h++) ladder.push(poseidon(ladder[h]!, ladder[h]!));
  emptyLadderCache.set(depth, ladder);
  return ladder;
}

export function emptyRoot(depth: number): bigint {
  return emptyLadder(depth)[depth]!;
}

abstract class BaseTree {
  readonly depth: number;
  /** nodes[level] maps index-at-level -> value; level 0 = leaves. */
  protected readonly nodes: Array<Map<bigint, bigint>>;
  protected readonly ladder: bigint[];

  constructor(depth: number) {
    this.depth = depth;
    this.ladder = emptyLadder(depth);
    this.nodes = Array.from({ length: depth + 1 }, () => new Map<bigint, bigint>());
  }

  protected node(level: number, index: bigint): bigint {
    return this.nodes[level]!.get(index) ?? this.ladder[level]!;
  }

  protected write(level: number, index: bigint, value: bigint): void {
    this.nodes[level]!.set(index, value);
  }

  protected setLeafInternal(index: bigint, value: bigint): void {
    if (index < 0n || index >= 1n << BigInt(this.depth)) throw new Error("leaf index out of range");
    this.write(0, index, value);
    let idx = index;
    for (let level = 0; level < this.depth; level++) {
      const parent = idx >> 1n;
      const left = this.node(level, parent << 1n);
      const right = this.node(level, (parent << 1n) | 1n);
      this.write(level + 1, parent, poseidon(left, right));
      idx = parent;
    }
  }

  root(): bigint {
    return this.node(this.depth, 0n);
  }

  leaf(index: FieldNumberish): bigint {
    return this.node(0, toField(index, "leaf index"));
  }

  /** LSB-first sibling path, leaf level upward (length = depth). */
  proof(index: FieldNumberish): bigint[] {
    const idx = toField(index, "leaf index");
    if (idx >= 1n << BigInt(this.depth)) throw new Error("leaf index out of range");
    const siblings: bigint[] = [];
    let cur = idx;
    for (let level = 0; level < this.depth; level++) {
      siblings.push(this.node(level, cur ^ 1n));
      cur >>= 1n;
    }
    return siblings;
  }

  static verify(depth: number, root: bigint, index: bigint, leaf: bigint, siblings: readonly bigint[]): boolean {
    if (siblings.length !== depth) return false;
    let cur = leaf;
    let idx = index;
    for (let level = 0; level < depth; level++) {
      const sibling = siblings[level]!;
      cur = (idx & 1n) === 0n ? poseidon(cur, sibling) : poseidon(sibling, cur);
      idx >>= 1n;
    }
    return cur === root;
  }
}

/** Depth-32 append-only note commitment tree (spec §15.4). */
export class AppendOnlyTree extends BaseTree {
  private next = 0n;

  get nextLeafIndex(): bigint {
    return this.next;
  }

  append(value: FieldNumberish): bigint {
    const index = this.next;
    if (index >= 1n << BigInt(this.depth)) throw new Error("tree full");
    this.setLeafInternal(index, toField(value, "leaf"));
    this.next = index + 1n;
    return index;
  }

  appendMany(values: readonly FieldNumberish[]): bigint {
    const first = this.next;
    for (const v of values) this.append(v);
    return first;
  }
}

/** Sparse mutable tree keyed LSB-first (identity registry depth 32, policy set depth 8). */
export class SparseTree extends BaseTree {
  set(index: FieldNumberish, value: FieldNumberish): void {
    this.setLeafInternal(toField(index, "leaf index"), toField(value, "leaf"));
  }
}
