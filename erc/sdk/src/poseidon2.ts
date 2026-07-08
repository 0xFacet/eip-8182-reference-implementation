// Poseidon2 BN254 t=4 RF=8 RP=56, x^5 sbox, length-tagged sponge (spec §15.3).
// Parameters embedded via poseidon-params.ts (verbatim copy of the published
// parameter asset) so the module works in browsers without filesystem access.

import { keccak_256 } from "@noble/hashes/sha3.js";
import { utf8ToBytes, bytesToHex } from "./bytes.ts";
import { BN254_SCALAR_MODULUS, type FieldNumberish, toField } from "./field.ts";
import {
  POSEIDON_EXTERNAL_MATRIX,
  POSEIDON_FIELD_MODULUS,
  POSEIDON_INTERNAL_DIAGONAL,
  POSEIDON_ROUND_CONSTANTS,
} from "./poseidon-params.ts";
import { DOMAIN_PREFIX } from "./generated/constants.ts";

const WIDTH = 4;
const RATE = 3;
const FULL_ROUNDS = 8;
const HALF_FULL_ROUNDS = FULL_ROUNDS / 2;
const PARTIAL_ROUNDS = 56;

const FIELD_MODULUS = BigInt(POSEIDON_FIELD_MODULUS);
if (FIELD_MODULUS !== BN254_SCALAR_MODULUS) {
  throw new Error("Poseidon params field modulus does not match BN254 scalar modulus");
}

const EXTERNAL_MATRIX = POSEIDON_EXTERNAL_MATRIX.map((row) => row.map(BigInt));
const INTERNAL_DIAGONAL = POSEIDON_INTERNAL_DIAGONAL.map(BigInt);
const ROUND_CONSTANTS = POSEIDON_ROUND_CONSTANTS.map(BigInt);

function mod(x: bigint): bigint {
  const r = x % FIELD_MODULUS;
  return r < 0n ? r + FIELD_MODULUS : r;
}

function pow5(x: bigint): bigint {
  const x2 = mod(x * x);
  return mod(mod(x2 * x2) * x);
}

function applyExternal(state: bigint[]): bigint[] {
  const out = new Array<bigint>(WIDTH).fill(0n);
  for (let i = 0; i < WIDTH; i++) {
    let acc = 0n;
    for (let j = 0; j < WIDTH; j++) acc = mod(acc + (EXTERNAL_MATRIX[i]![j] ?? 0n) * (state[j] ?? 0n));
    out[i] = acc;
  }
  return out;
}

function applyInternal(state: bigint[]): bigint[] {
  let sum = 0n;
  for (let i = 0; i < WIDTH; i++) sum = mod(sum + (state[i] ?? 0n));
  return state.map((s, i) => mod(sum + (INTERNAL_DIAGONAL[i] ?? 0n) * s));
}

function permutation(input: bigint[]): bigint[] {
  let state = applyExternal([...input]);
  for (let r = 0; r < HALF_FULL_ROUNDS; r++) {
    for (let i = 0; i < WIDTH; i++) state[i] = mod((state[i] ?? 0n) + (ROUND_CONSTANTS[r * WIDTH + i] ?? 0n));
    for (let i = 0; i < WIDTH; i++) state[i] = pow5(state[i] ?? 0n);
    state = applyExternal(state);
  }
  for (let r = 0; r < PARTIAL_ROUNDS; r++) {
    state[0] = mod((state[0] ?? 0n) + (ROUND_CONSTANTS[HALF_FULL_ROUNDS * WIDTH + r] ?? 0n));
    state[0] = pow5(state[0] ?? 0n);
    state = applyInternal(state);
  }
  for (let r = 0; r < HALF_FULL_ROUNDS; r++) {
    const base = HALF_FULL_ROUNDS * WIDTH + PARTIAL_ROUNDS + r * WIDTH;
    for (let i = 0; i < WIDTH; i++) state[i] = mod((state[i] ?? 0n) + (ROUND_CONSTANTS[base + i] ?? 0n));
    for (let i = 0; i < WIDTH; i++) state[i] = pow5(state[i] ?? 0n);
    state = applyExternal(state);
  }
  return state;
}

export function poseidon(...inputs: readonly FieldNumberish[]): bigint {
  const values = inputs.map((x) => toField(x, "poseidon input"));
  let state: bigint[] = [0n, 0n, 0n, BigInt(values.length) << 64n];
  if (values.length === 0) {
    return permutation(state)[0]!;
  }
  for (let chunk = 0; chunk * RATE < values.length; chunk += 1) {
    for (let slot = 0; slot < RATE; slot += 1) {
      const input = values[chunk * RATE + slot];
      if (input !== undefined) state[slot] = mod((state[slot] ?? 0n) + input);
    }
    state = permutation(state);
  }
  return state[0]!;
}

/** keccak256(DOMAIN_PREFIX + name) mod p — spec §15.5. */
export function domainTag(name: string): bigint {
  return BigInt(bytesToHex(keccak_256(utf8ToBytes(`${DOMAIN_PREFIX}${name}`)))) % FIELD_MODULUS;
}
