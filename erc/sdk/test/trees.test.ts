import { describe, expect, it } from "vitest";
import { poseidon } from "../src/poseidon2.ts";
import { AppendOnlyTree, SparseTree, emptyLadder, emptyRoot } from "../src/trees.ts";

describe("empty ladder", () => {
  it("EMPTY[h+1] = poseidon(EMPTY[h], EMPTY[h]) with EMPTY[0] = 0", () => {
    const ladder = emptyLadder(8);
    expect(ladder[0]).toBe(0n);
    for (let h = 0; h < 8; h++) expect(ladder[h + 1]).toBe(poseidon(ladder[h]!, ladder[h]!));
  });

  it("fresh trees start at the empty root", () => {
    expect(new AppendOnlyTree(32).root()).toBe(emptyRoot(32));
    expect(new SparseTree(8).root()).toBe(emptyRoot(8));
  });
});

describe("append-only tree", () => {
  it("append + proof verifies against root, LSB-first", () => {
    const tree = new AppendOnlyTree(32);
    const leaves = [111n, 222n, 333n, 444n, 555n];
    for (const leaf of leaves) tree.append(leaf);
    expect(tree.nextLeafIndex).toBe(5n);
    for (let i = 0; i < leaves.length; i++) {
      const siblings = tree.proof(i);
      expect(siblings).toHaveLength(32);
      expect(AppendOnlyTree.verify(32, tree.root(), BigInt(i), leaves[i]!, siblings)).toBe(true);
      expect(AppendOnlyTree.verify(32, tree.root(), BigInt(i), leaves[i]! + 1n, siblings)).toBe(false);
    }
  });

  it("manual depth-2 root cross-check (LSB-first ordering)", () => {
    const tree = new AppendOnlyTree(2);
    tree.append(10n);
    tree.append(20n);
    tree.append(30n);
    // leaves: [10, 20, 30, EMPTY0=0]
    const expected = poseidon(poseidon(10n, 20n), poseidon(30n, 0n));
    expect(tree.root()).toBe(expected);
  });
});

describe("sparse tree", () => {
  it("set/update/proof at arbitrary positions", () => {
    const tree = new SparseTree(32);
    tree.set(1n, 1000n); // registry positions start at 1
    tree.set(2n, 2000n);
    tree.set(1n, 1001n); // mutable
    expect(tree.leaf(1n)).toBe(1001n);
    expect(SparseTree.verify(32, tree.root(), 1n, 1001n, tree.proof(1n))).toBe(true);
    expect(SparseTree.verify(32, tree.root(), 2n, 2000n, tree.proof(2n))).toBe(true);
    expect(SparseTree.verify(32, tree.root(), 3n, 0n, tree.proof(3n))).toBe(true); // empty membership
  });

  it("depth-8 policy-set tree with slot 0 and slot 5", () => {
    const tree = new SparseTree(8);
    tree.set(0n, 42n);
    tree.set(5n, 43n);
    expect(SparseTree.verify(8, tree.root(), 5n, 43n, tree.proof(5n))).toBe(true);
  });
});
