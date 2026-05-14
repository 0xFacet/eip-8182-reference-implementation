// Build a worst-case witness input for the pool circuit:
//   transfer (operationKind=0, derived from publicAmountOut == 0)
//   2 real inputs, 3 real outputs (no phantoms, no dummies)
//   fee slot used (slot 2 active)
//   all 3 output slots locked (lockedOutputBinding != 0 paired with flag bits 0/1/2)
//
// Computes all derived values (commitments, nullifiers, Merkle roots)
// off-circuit using scripts/poseidon2.js so the circuit's checks all pass.
//
// Output: build/pool/input.json — directly consumable by the wasm witness gen.
//
// Witness shape MUST track circuits/pool/pool.circom — fields the circuit
// derives (path bits, leaf-index bits, operationKind, output token slots) are
// NOT included; canonical tokenAddress, intent owner-hashes, and policy-set
// state are.

const fs = require('fs');
const path = require('path');
const { poseidon, P } = require('./poseidon2');
const { keccak256 } = require('ethereum-cryptography/keccak');
const { utf8ToBytes } = require('ethereum-cryptography/utils');

const ROOT = path.resolve(__dirname, '../..');
const TAGS = JSON.parse(fs.readFileSync(path.join(ROOT, 'build/domain_tags.json'), 'utf8'));
const T = Object.fromEntries(Object.entries(TAGS).map(([k,v]) => [k, BigInt(v)]));

// ---- Helpers ----
function buildEmptyHashes(depth) {
  const e = [0n];
  for (let h = 0; h < depth; h++) e.push(poseidon(e[h], e[h]));
  return e;
}

function noteCommitmentTreeRoot(leaves, depth) {
  const empty = buildEmptyHashes(depth);
  let level = new Map(leaves);
  for (let h = 0; h < depth; h++) {
    const next = new Map();
    for (const [pos] of level) {
      const sib = pos ^ 1;
      const left  = (pos & 1) ? (level.get(sib) ?? empty[h]) : level.get(pos);
      const right = (pos & 1) ? level.get(pos)               : (level.get(sib) ?? empty[h]);
      next.set(pos >> 1, poseidon(left, right));
    }
    level = next;
  }
  return level.get(0) ?? empty[depth];
}

function noteCommitmentSiblings(leafIdx, leaves, depth) {
  const empty = buildEmptyHashes(depth);
  const sibs = [];
  let pos = leafIdx;
  let level = new Map(leaves);
  for (let h = 0; h < depth; h++) {
    const sibPos = pos ^ 1;
    sibs.push(level.get(sibPos) ?? empty[h]);
    const next = new Map();
    for (const [p] of level) {
      const sib = p ^ 1;
      const left  = (p & 1) ? (level.get(sib) ?? empty[h]) : level.get(p);
      const right = (p & 1) ? level.get(p)                  : (level.get(sib) ?? empty[h]);
      next.set(p >> 1, poseidon(left, right));
    }
    level = next;
    pos = pos >> 1;
  }
  return sibs;
}

// Sparse depth-D tree, keyed LSB-first. Single-leaf or few-leaf flows.
function buildSparseRootAndSiblings(leafByKey, depth, queryKey) {
  const empty = buildEmptyHashes(depth);
  const nodes = new Map();
  const k = (h, idx) => `${h}:${idx}`;
  for (const [key, leaf] of leafByKey) {
    nodes.set(k(0, BigInt(key).toString()), leaf);
  }
  for (let h = 0; h < depth; h++) {
    const prefixes = new Set();
    for (const kk of nodes.keys()) {
      const [hStr, idxStr] = kk.split(':');
      if (Number(hStr) !== h) continue;
      prefixes.add(BigInt(idxStr) >> 1n);
    }
    for (const pfx of prefixes) {
      const left  = nodes.get(k(h, (pfx << 1n).toString()))         ?? empty[h];
      const right = nodes.get(k(h, ((pfx << 1n) | 1n).toString()))  ?? empty[h];
      nodes.set(k(h + 1, pfx.toString()), poseidon(left, right));
    }
  }
  const root = nodes.get(k(depth, '0')) ?? empty[depth];

  const sibs = [];
  let pos = BigInt(queryKey);
  for (let h = 0; h < depth; h++) {
    const sibIdx = (pos >> BigInt(h)) ^ 1n;
    sibs.push(nodes.get(k(h, sibIdx.toString())) ?? empty[h]);
  }
  return { root, sibs };
}

// ---- Sender identity ----
const senderOwnerNullifierKey = 0xCAFE0001n;
const senderNoteSecretSeed    = 0xCAFE0002n;
const authorizingAddress      = 0x1111111111111111111111111111111111111111n;

const senderOwnerNullifierKeyHash = poseidon(T.OWNER_NULLIFIER_KEY_HASH_DOMAIN, senderOwnerNullifierKey);
const senderNoteSecretSeedHash    = poseidon(T.NOTE_SECRET_SEED_DOMAIN,         senderNoteSecretSeed);

// ---- Canonical token (single witness shared across real inputs/outputs) ----
const tokenAddress = 0x2222222222222222222222222222222222222222n;

// ---- Inputs (2 real notes, both spent, owned by sender) ----
const inIsReal      = [1n, 1n];
const inAmount      = [10n, 5n];
const inNoteSecret  = [0xDEADBEEF01n, 0xDEADBEEF02n];
const inLeafIndex   = [0n, 1n];

const inOwnerCommitment = inAmount.map((_, i) =>
  poseidon(T.OWNER_COMMITMENT_DOMAIN, senderOwnerNullifierKeyHash, inNoteSecret[i]));
const inNoteBodyCommitment = inAmount.map((_, i) =>
  poseidon(T.NOTE_BODY_COMMITMENT_DOMAIN, inOwnerCommitment[i], inAmount[i], tokenAddress));
const inNoteCommitment = inAmount.map((_, i) =>
  poseidon(T.NOTE_COMMITMENT_DOMAIN, inNoteBodyCommitment[i], inLeafIndex[i]));
const inRealNullifier = inAmount.map((_, i) =>
  poseidon(T.NULLIFIER_DOMAIN, inNoteCommitment[i], senderOwnerNullifierKey));

const noteLeaves = new Map([
  [Number(inLeafIndex[0]), inNoteCommitment[0]],
  [Number(inLeafIndex[1]), inNoteCommitment[1]],
]);
const noteCommitmentRoot = noteCommitmentTreeRoot(noteLeaves, 32);
const inSiblings = inLeafIndex.map(idx => noteCommitmentSiblings(Number(idx), noteLeaves, 32));

// ---- Outputs (all 3 real) ----
const outIsReal = [1n, 1n, 1n];
const outAmount = [8n, 5n, 2n]; // 8+5+2 = 15 = 10+5 input total, publicAmountOut = 0

const outOwnerNullifierKey = [
  0xBABE0001n,                  // recipient's key
  senderOwnerNullifierKey,      // sender's own key for change
  0xBABE0003n,                  // fee recipient's key
];
const outOwnerNullifierKeyHash = outOwnerNullifierKey.map(k =>
  poseidon(T.OWNER_NULLIFIER_KEY_HASH_DOMAIN, k));

// ---- Operation mode + intent fields ----
//   operationKind is derived from publicAmountOut by the circuit; transfer
//   here means publicAmountOut == 0.
const recipientOwnerNullifierKeyHash        = outOwnerNullifierKeyHash[0];
const feeNoteRecipientOwnerNullifierKeyHash = outOwnerNullifierKeyHash[2];
const feeAmount             = outAmount[2];
const nonce                 = 0x9F3A1C7E5B2D4F86n;
const executionConstraintsFlags = 0n;
const validUntilSeconds     = 1735689600n;
const executionChainId      = 1n;

// ---- Auth-policy registry + policy-set ----
const authVerifier        = 0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1n;
const authSecret          = 0xA0701337n;
const authDataCommitment  = poseidon(T.POLICY_COMMITMENT_DOMAIN, authSecret);
const blindingFactor      = 0xB17ED15ABCDEF0123456789ABCDEF01n;
const registrationBlinder = 0xCC00CC00CC00CC00n;

// One policy at policy-set slot 0 → policySetCommitment is the depth-8
// sparse root for this single leaf. policyCommitment is the leaf value.
const policyCommitment = poseidon(
  T.POLICY_COMMITMENT_DOMAIN, authVerifier, authDataCommitment, registrationBlinder,
);
const policySetLeafPosition = 0n;
const POLICY_SET_DEPTH = 8;
const policySetBuilt = buildSparseRootAndSiblings(
  [[policySetLeafPosition, policyCommitment]], POLICY_SET_DEPTH, policySetLeafPosition,
);
const policySetCommitment = policySetBuilt.root;
const policySetSiblings   = policySetBuilt.sibs;

// Auth-policy registry leaf: leafPosition 1 (slot 0 reserved as the
// unassigned sentinel; first setAuthPolicy from sender gets leafPosition 1).
const leafPosition = 1n;
const authPolicyLeaf = poseidon(
  T.AUTH_POLICY_DOMAIN,
  authorizingAddress,
  senderOwnerNullifierKeyHash,
  senderNoteSecretSeedHash,
  policySetCommitment,
);
const AUTH_POLICY_TREE_DEPTH = 32;
const authPolicyBuilt = buildSparseRootAndSiblings(
  [[leafPosition, authPolicyLeaf]], AUTH_POLICY_TREE_DEPTH, leafPosition,
);
const authPolicyRoot     = authPolicyBuilt.root;
const authPolicySiblings = authPolicyBuilt.sibs;

// ---- Output noteSecrets, body commitments, intent replay ID ----
const intentReplayId = poseidon(T.INTENT_REPLAY_ID_DOMAIN, senderOwnerNullifierKey,
                                 authorizingAddress, executionChainId, nonce);

const outNoteSecret = [0,1,2].map(i =>
  poseidon(T.TRANSACT_NOTE_SECRET_DOMAIN, senderNoteSecretSeed, intentReplayId, BigInt(i)));
const outOwnerCommitment = [0,1,2].map(i =>
  poseidon(T.OWNER_COMMITMENT_DOMAIN, outOwnerNullifierKeyHash[i], outNoteSecret[i]));
// All 3 outputs are real, so the body's tokenAddress field == canonical token.
// Dummy outputs would use 0 here (circuit: outBodyToken = outIsReal * tokenAddress).
const outNoteBodyCommitment = [0,1,2].map(i =>
  poseidon(T.NOTE_BODY_COMMITMENT_DOMAIN, outOwnerCommitment[i], outAmount[i], tokenAddress));

// ---- outputNoteData hashes + locked output bindings ----
const OUTPUT_NOTE_DATA = ['eip-8182-output-0', 'eip-8182-output-1', 'eip-8182-output-2'];
const outputNoteDataHash = OUTPUT_NOTE_DATA.map(s => {
  const h = keccak256(utf8ToBytes(s));
  let v = 0n;
  for (const b of h) v = (v << 8n) | BigInt(b);
  return v % P;
});
const outLockedOutputBinding = [0,1,2].map(i =>
  poseidon(T.OUTPUT_BINDING_DOMAIN, outNoteBodyCommitment[i], outputNoteDataHash[i]));

// All 3 slots locked => executionConstraintsFlags has bits 0/1/2 set (= 7).
// (Spec Section 8.10: flag bit i pairs with lockedOutputBinding_i.)
const execFlagsWorstCase = 7n;

// ---- Public values ----
const publicAmountOut         = 0n;     // transfer
const publicRecipientAddress  = 0n;
const publicTokenAddress      = 0n;

// ---- Blinded auth commitment + intent digest ----
//   Transfer mode: digest's amount == outAmount[0] (recipient amount),
//                  tokenAddress == canonical token, operationKind == 0.
const blindedAuthCommitment = poseidon(T.BLINDED_AUTH_COMMITMENT_DOMAIN, authDataCommitment, blindingFactor);
const transactionIntentDigest = poseidon(
  T.TRANSACTION_INTENT_DIGEST_DOMAIN,
  authVerifier,
  authorizingAddress,
  0n,                                       // operationKind = TRANSFER_OP
  tokenAddress,
  recipientOwnerNullifierKeyHash,
  outAmount[0],                             // recipient amount
  feeNoteRecipientOwnerNullifierKeyHash,
  feeAmount,
  publicRecipientAddress,                   // 0 in transfer
  execFlagsWorstCase,
  outLockedOutputBinding[0],
  outLockedOutputBinding[1],
  outLockedOutputBinding[2],
  nonce,
  validUntilSeconds,
  executionChainId,
);

// ---- Assemble input.json ----
const toStr = v => (typeof v === 'bigint' ? v.toString() : String(v));
const arr   = a => a.map(toStr);
const arr2  = a => a.map(arr);

const out = {
  // public (19)
  noteCommitmentRoot:          toStr(noteCommitmentRoot),
  nullifier0:                  toStr(inRealNullifier[0]),
  nullifier1:                  toStr(inRealNullifier[1]),
  noteBodyCommitment0:         toStr(outNoteBodyCommitment[0]),
  noteBodyCommitment1:         toStr(outNoteBodyCommitment[1]),
  noteBodyCommitment2:         toStr(outNoteBodyCommitment[2]),
  publicAmountOut:             toStr(publicAmountOut),
  publicRecipientAddress:      toStr(publicRecipientAddress),
  publicTokenAddress:          toStr(publicTokenAddress),
  intentReplayId:              toStr(intentReplayId),
  validUntilSeconds:           toStr(validUntilSeconds),
  executionChainId:            toStr(executionChainId),
  authPolicyRoot:              toStr(authPolicyRoot),
  outputNoteDataHash0:         toStr(outputNoteDataHash[0]),
  outputNoteDataHash1:         toStr(outputNoteDataHash[1]),
  outputNoteDataHash2:         toStr(outputNoteDataHash[2]),
  authVerifier:                toStr(authVerifier),
  blindedAuthCommitment:       toStr(blindedAuthCommitment),
  transactionIntentDigest:     toStr(transactionIntentDigest),

  // private — sender + leaf state
  senderOwnerNullifierKey:     toStr(senderOwnerNullifierKey),
  senderNoteSecretSeed:        toStr(senderNoteSecretSeed),
  authorizingAddress:          toStr(authorizingAddress),
  noteSecretSeedHash:          toStr(senderNoteSecretSeedHash),
  policySetCommitment:         toStr(policySetCommitment),
  leafPosition:                toStr(leafPosition),
  authPolicySiblings:          arr(authPolicySiblings),

  // private — inputs
  inIsReal:                    arr(inIsReal),
  inAmount:                    arr(inAmount),
  inNoteSecret:                arr(inNoteSecret),
  inLeafIndex:                 arr(inLeafIndex),
  inSiblings:                  arr2(inSiblings),

  // private — outputs
  outIsReal:                   arr(outIsReal),
  outAmount:                   arr(outAmount),
  outOwnerNullifierKeyHash:    arr(outOwnerNullifierKeyHash),
  outLockedOutputBinding:      arr(outLockedOutputBinding),

  // private — canonical token
  tokenAddress:                toStr(tokenAddress),

  // private — intent fields
  recipientOwnerNullifierKeyHash:        toStr(recipientOwnerNullifierKeyHash),
  feeNoteRecipientOwnerNullifierKeyHash: toStr(feeNoteRecipientOwnerNullifierKeyHash),
  feeAmount:                             toStr(feeAmount),
  nonce:                                 toStr(nonce),
  executionConstraintsFlags:             toStr(execFlagsWorstCase),

  // private — auth-policy proof witnesses
  authDataCommitment:          toStr(authDataCommitment),
  blindingFactor:              toStr(blindingFactor),
  registrationBlinder:         toStr(registrationBlinder),
  policySetLeafPosition:       toStr(policySetLeafPosition),
  policySetSiblings:           arr(policySetSiblings),
};

const outPath = path.join(ROOT, 'build/pool/input.json');
fs.mkdirSync(path.dirname(outPath), { recursive: true });
fs.writeFileSync(outPath, JSON.stringify(out, null, 2));
console.log(`wrote ${outPath}`);
