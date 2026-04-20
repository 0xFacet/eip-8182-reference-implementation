// EIP-8182 Poseidon2 adapter.
//
// Wraps @aztec/bb.js's native Poseidon2 sponge (length-tagged, capacity =
// message_size << 64) and exposes bigint-friendly helpers that match the
// normative `poseidon(x_1, ..., x_N) = Poseidon2_sponge(x_1, ..., x_N)`
// construction in EIP-8182 §3.3 byte-for-byte.
//
// The 2-input `poseidon2HashPair` form is the Merkle internal hash. It uses
// the length-tagged sponge — NOT the bare permutation form initialized with
// capacity 0 used by some Poseidon2 Merkle tree libraries.

import { BarretenbergSync } from "@aztec/bb.js";

let _sync: BarretenbergSync | null = null;
let _initPromise: Promise<BarretenbergSync> | null = null;

async function getSync(): Promise<BarretenbergSync> {
  if (_sync) return _sync;
  if (!_initPromise) _initPromise = BarretenbergSync.new();
  _sync = await _initPromise;
  return _sync;
}

/** Initialise the underlying bb.js backend. Call once before using any sync API. */
export async function initPoseidon2(): Promise<void> {
  await getSync();
}

function fieldToBytes(x: bigint): Uint8Array {
  if (x < 0n) throw new Error("field element must be non-negative");
  const hex = x.toString(16).padStart(64, "0");
  if (hex.length > 64) throw new Error(`field element exceeds 32 bytes: 0x${hex}`);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToField(b: Uint8Array): bigint {
  let n = 0n;
  for (const byte of b) {
    n = (n << 8n) | BigInt(byte);
  }
  return n;
}

/**
 * Hash an arbitrary number of field elements under the Poseidon2 sponge.
 * Produces `state[0]` after absorbing inputs in rate-3 chunks with
 * capacity IV = (N << 64). Matches `Poseidon2::hash(input, N)` in Noir
 * and `Poseidon2Sponge.hash(...)` in Solidity.
 */
export function poseidon2Hash(inputs: bigint[]): bigint {
  const sync = _sync;
  if (!sync) {
    throw new Error("Poseidon2 not initialised — call initPoseidon2() first.");
  }
  const packed = inputs.map(fieldToBytes);
  const result = sync.poseidon2Hash({ inputs: packed });
  return bytesToField(result.hash);
}

/** Two-input Merkle-internal hash. Length-tagged sponge form `[a, b, 0, 2<<64]`. */
export function poseidon2HashPair(a: bigint, b: bigint): bigint {
  return poseidon2Hash([a, b]);
}

/**
 * Derive the empty-node ladder for a binary Merkle tree of given `depth`,
 * starting at the empty-leaf value. Entry `i` is the empty-subtree hash at
 * level `i`: `ladder[0] = emptyLeaf`, `ladder[i+1] = poseidon(ladder[i], ladder[i])`.
 */
export function poseidon2EmptyLadder(depth: number, emptyLeaf: bigint = 0n): bigint[] {
  const ladder: bigint[] = [emptyLeaf];
  for (let i = 1; i <= depth; i++) {
    ladder.push(poseidon2HashPair(ladder[i - 1], ladder[i - 1]));
  }
  return ladder;
}

/** Convenience: await-friendly init plus hash in one call (for ad-hoc callers). */
export async function poseidon2HashAsync(inputs: bigint[]): Promise<bigint> {
  await getSync();
  return poseidon2Hash(inputs);
}
