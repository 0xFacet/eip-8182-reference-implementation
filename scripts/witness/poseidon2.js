// JS reference Poseidon2 BN254 t=4 RF=8 RP=56, sbox=x^5, length-tagged sponge.
// Used by the witness generator to compute Merkle roots / commitment values
// off-circuit. Self-checks against assets/eip-8182/poseidon2_vectors.json.

const fs = require('fs');
const path = require('path');

const REPO_ROOT = path.resolve(__dirname, '../..');
const ASSET = path.join(REPO_ROOT, 'assets/eip-8182/poseidon2_bn254_t4_rf8_rp56.json');
const VECTORS = path.join(REPO_ROOT, 'assets/eip-8182/poseidon2_vectors.json');

const params = JSON.parse(fs.readFileSync(ASSET, 'utf8'));
const P = BigInt(params.fieldModulus);
const T = params.stateWidth;             // 4
const RF = params.fullRounds;            // 8
const HALF_RF = RF / 2;                  // 4
const RP = params.partialRounds;         // 56
const RC = params.roundConstants.map(BigInt);
const INT_DIAG = params.internalDiagonal.map(BigInt);

// External matrix (asset is the 4x4 [[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]])
const ME = params.externalMatrix.map(row => row.map(BigInt));

// Modular helpers
const mod = x => { x = x % P; return x < 0n ? x + P : x; };

function pow5(x)        { const x2 = mod(x*x); return mod(mod(x2*x2)*x); }
function addRC(state, base) { for (let i = 0; i < T; i++) state[i] = mod(state[i] + RC[base + i]); }
function addRC0(state, c)   { state[0] = mod(state[0] + RC[c]); }

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
  // First-half full rounds
  for (let r = 0; r < HALF_RF; r++) {
    addRC(state, r * T);
    for (let i = 0; i < T; i++) state[i] = pow5(state[i]);
    state = applyME(state);
  }
  // Partial rounds
  for (let r = 0; r < RP; r++) {
    addRC0(state, HALF_RF * T + r);
    state[0] = pow5(state[0]);
    state = applyMI(state);
  }
  // Second-half full rounds
  for (let r = 0; r < HALF_RF; r++) {
    addRC(state, HALF_RF * T + RP + r * T);
    for (let i = 0; i < T; i++) state[i] = pow5(state[i]);
    state = applyME(state);
  }
  return state;
}

// Length-tagged sponge per spec Section 3.3
function poseidon(...inputs) {
  const N = inputs.length;
  const lenTag = BigInt(N) << 64n;
  let state = [0n, 0n, 0n, lenTag];
  if (N === 0) {
    state = permutation(state);
    return state[0];
  }
  for (let c = 0; c * 3 < N; c++) {
    for (let j = 0; j < 3; j++) {
      const idx = c * 3 + j;
      if (idx < N) state[j] = mod(state[j] + BigInt(inputs[idx]));
    }
    state = permutation(state);
  }
  return state[0];
}

if (require.main === module) {
  const vecs = JSON.parse(fs.readFileSync(VECTORS, 'utf8')).poseidonVectors;
  let pass = 0, fail = 0;
  for (const v of vecs) {
    const got = poseidon(...v.inputs.map(BigInt));
    const want = BigInt(v.output);
    if (got === want) { pass++; }
    else { fail++; console.log(`FAIL arity=${v.inputs.length} expected=0x${want.toString(16)} got=0x${got.toString(16)}`); }
  }
  console.log(`${pass}/${pass+fail} vectors pass`);
  process.exit(fail ? 1 : 0);
}

module.exports = { poseidon, P };
