// Poseidon2 BN254 t=4 RF=8 RP=56, x^5 sbox, length-tagged sponge (spec §15.3).
// Self-contained ESM port of scripts/witness/poseidon2.js from the 8182 tree,
// reading the parameter asset copied verbatim into erc/assets.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ASSET = path.join(HERE, "../../assets/poseidon2_bn254_t4_rf8_rp56.json");

const params = JSON.parse(fs.readFileSync(ASSET, "utf8"));
export const P = BigInt(params.fieldModulus);
const T = params.stateWidth; // 4
const RF = params.fullRounds; // 8
const HALF_RF = RF / 2;
const RP = params.partialRounds; // 56
const RC = params.roundConstants.map(BigInt);
const INT_DIAG = params.internalDiagonal.map(BigInt);
const ME = params.externalMatrix.map((row) => row.map(BigInt));

const mod = (x) => {
  x = x % P;
  return x < 0n ? x + P : x;
};

function pow5(x) {
  const x2 = mod(x * x);
  return mod(mod(x2 * x2) * x);
}

function applyME(state) {
  const out = new Array(T).fill(0n);
  for (let i = 0; i < T; i++) {
    let s = 0n;
    for (let j = 0; j < T; j++) s = mod(s + ME[i][j] * state[j]);
    out[i] = s;
  }
  return out;
}

function applyMI(state) {
  let sum = 0n;
  for (let i = 0; i < T; i++) sum = mod(sum + state[i]);
  return state.map((s, i) => mod(sum + INT_DIAG[i] * s));
}

function permutation(stateIn) {
  let state = applyME([...stateIn]);
  for (let r = 0; r < HALF_RF; r++) {
    for (let i = 0; i < T; i++) state[i] = mod(state[i] + RC[r * T + i]);
    for (let i = 0; i < T; i++) state[i] = pow5(state[i]);
    state = applyME(state);
  }
  for (let r = 0; r < RP; r++) {
    state[0] = mod(state[0] + RC[HALF_RF * T + r]);
    state[0] = pow5(state[0]);
    state = applyMI(state);
  }
  for (let r = 0; r < HALF_RF; r++) {
    const base = HALF_RF * T + RP + r * T;
    for (let i = 0; i < T; i++) state[i] = mod(state[i] + RC[base + i]);
    for (let i = 0; i < T; i++) state[i] = pow5(state[i]);
    state = applyME(state);
  }
  return state;
}

export function poseidon(...inputs) {
  const vals = inputs.map((x) => mod(BigInt(x)));
  let state = [0n, 0n, 0n, BigInt(vals.length) << 64n];
  if (vals.length === 0) return permutation(state)[0];
  for (let off = 0; off < vals.length; off += 3) {
    for (let j = 0; j < 3; j++) {
      if (off + j < vals.length) state[j] = mod(state[j] + vals[off + j]);
    }
    state = permutation(state);
  }
  return state[0];
}
