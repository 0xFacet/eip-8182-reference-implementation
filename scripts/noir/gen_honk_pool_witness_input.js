// Variant of scripts/witness/gen_pool_witness_input.js for the Honk auth flow:
//   - authorizingAddress is derived from a deterministic secp256k1 keypair
//     (matches what the Noir auth circuit's pubkey-binding produces).
//   - authVerifier is the address where RealAuthVerifier will be etched in
//     the integration test.
//   - authDataCommitment uses the pubkey-half formula
//     (privacy_pool_common::crypto::secp256k1_auth_commitment from 71e7d72)
//     instead of the demo's poseidon(POLICY_DOMAIN, authSecret).
//
// Modes (--mode=, default transfer):
//   - transfer:        publicAmountOut=0, slot 0 is recipient note,
//                      slot 1 is sender's change, slot 2 is fee note.
//   - withdraw_eth:    publicAmountOut>0, canonical tokenAddress=0,
//                      publicTokenAddress=0; slot 0 = sender change,
//                      slot 1 dummy, slot 2 fee.
//   - withdraw_erc20:  publicAmountOut>0, canonical tokenAddress=token,
//                      publicTokenAddress=token; slots same as withdraw_eth.
//
// Output: build/integration_honk/<mode>_pool_input.json (one per mode so
// the three sessions don't overwrite each other).

const fs = require('fs');
const path = require('path');
const { poseidon, P } = require('../witness/poseidon2');
const { keccak256 } = require('ethereum-cryptography/keccak');
const { utf8ToBytes } = require('ethereum-cryptography/utils');

const ROOT = path.resolve(__dirname, '../..');
const TAGS = JSON.parse(fs.readFileSync(path.join(ROOT, 'build/domain_tags.json'), 'utf8'));
const T = Object.fromEntries(Object.entries(TAGS).map(([k,v]) => [k, BigInt(v)]));

// Sidecar values produced by scripts/noir/gen_prover_toml.js (deterministic
// for the default test keypair).
const SIDECAR = JSON.parse(fs.readFileSync(
  path.join(ROOT, 'build/noir_auth/session_sidecar.json'),
  'utf8',
));
const PUBKEY_DERIVED_AUTHORIZING_ADDR = BigInt(SIDECAR.pubkey_eth_address);
const REAL_AUTH_VERIFIER_ADDR         = BigInt(SIDECAR.auth_verifier_address);
const REAL_AUTH_DATA_COMMITMENT       = BigInt(SIDECAR.auth_data_commitment_dec);
const REAL_BLINDING_FACTOR            = BigInt(SIDECAR.blinding_factor_hex);

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

// Sparse depth-D tree, keyed LSB-first.
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
const authorizingAddress      = PUBKEY_DERIVED_AUTHORIZING_ADDR;

const senderOwnerNullifierKeyHash = poseidon(T.OWNER_NULLIFIER_KEY_HASH_DOMAIN, senderOwnerNullifierKey);
const senderNoteSecretSeedHash    = poseidon(T.NOTE_SECRET_SEED_DOMAIN,         senderNoteSecretSeed);

// ---- Mode (transfer | withdraw_eth | withdraw_erc20) ----
const MODE = (() => {
  const flag = process.argv.find(a => a.startsWith('--mode='));
  const v = flag ? flag.slice('--mode='.length) : 'transfer';
  if (!['transfer', 'withdraw_eth', 'withdraw_erc20'].includes(v)) {
    throw new Error(`bad --mode: ${v}`);
  }
  return v;
})();
const IS_WITHDRAW = MODE !== 'transfer';

// ---- Canonical token ----
const tokenAddress = MODE === 'withdraw_eth'
  ? 0n
  : 0x2222222222222222222222222222222222222222n;

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

// ---- Outputs ----
//   transfer: all 3 real. amounts = [8, 5, 2]; sum=15 = inputs(10+5).
//   withdraw: slot 1 dummy (circuit constraint), slot 0 = change to sender,
//             slot 2 = fee. amounts = [5, 0, 2]; sum=7 + publicAmountOut(8) = 15.
const outIsReal = IS_WITHDRAW ? [1n, 0n, 1n] : [1n, 1n, 1n];
const outAmount = IS_WITHDRAW ? [5n, 0n, 2n] : [8n, 5n, 2n];

const DUMMY_OWNER_NULLIFIER_KEY = 0xdeadn;
const outOwnerNullifierKey = IS_WITHDRAW ? [
  senderOwnerNullifierKey,         // sender's own key for change
  DUMMY_OWNER_NULLIFIER_KEY,       // dummy: 0xdead per spec Section 3.2
  0xBABE0003n,                     // fee recipient's key
] : [
  0xBABE0001n,                     // recipient's key
  senderOwnerNullifierKey,         // sender's own key for change
  0xBABE0003n,                     // fee recipient's key
];
const outOwnerNullifierKeyHash = outOwnerNullifierKey.map(k =>
  poseidon(T.OWNER_NULLIFIER_KEY_HASH_DOMAIN, k));

// ---- Operation mode + intent fields ----
//
// In withdraw mode, the recipient identity is the public withdrawal
// destination (`publicRecipientAddress`); the intent's recipient-owner-hash
// MUST be zero. Fee recipient is always identified by owner-hash.
const recipientOwnerNullifierKeyHash = IS_WITHDRAW
  ? 0n
  : outOwnerNullifierKeyHash[0];
const feeNoteRecipientOwnerNullifierKeyHash = outOwnerNullifierKeyHash[2];
const feeAmount             = outAmount[2];
const nonce                 = 0x9F3A1C7E5B2D4F86n;
const executionConstraintsFlags = 0n;
const validUntilSeconds     = 1735689600n;
const executionChainId      = 1n;

// ---- Auth-policy registry + policy-set ----
const authVerifier        = REAL_AUTH_VERIFIER_ADDR;
const authDataCommitment  = REAL_AUTH_DATA_COMMITMENT;
const blindingFactor      = REAL_BLINDING_FACTOR;
const registrationBlinder = 0xCC00CC00CC00CC00n;

const policyCommitment = poseidon(
  T.POLICY_COMMITMENT_DOMAIN, authVerifier, authDataCommitment, registrationBlinder,
);
const POLICY_SET_DEPTH = 8;
const policySetLeafPosition = 0n;
const policySetBuilt = buildSparseRootAndSiblings(
  [[policySetLeafPosition, policyCommitment]], POLICY_SET_DEPTH, policySetLeafPosition,
);
const policySetCommitment = policySetBuilt.root;
const policySetSiblings   = policySetBuilt.sibs;

// First setAuthPolicy from sender goes to leafPosition 1 (slot 0 reserved).
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
// Circuit gates body's token field by realness:
//   outBodyToken[i] = outIsReal[i] * tokenAddress   (dummy => 0)
const outNoteBodyCommitment = [0,1,2].map(i => {
  const bodyToken = outIsReal[i] === 0n ? 0n : tokenAddress;
  return poseidon(T.NOTE_BODY_COMMITMENT_DOMAIN, outOwnerCommitment[i], outAmount[i], bodyToken);
});

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
const execFlagsWorstCase = 7n;

// ---- Public values + intent digest amount ----
//   Transfer:  publicAmountOut=0, publicTokenAddress=0, publicRecipientAddress=0,
//              digest.amount == outAmount[0].
//   Withdraw:  publicAmountOut>0, publicTokenAddress==canonical, publicRecipientAddress!=0,
//              digest.amount == publicAmountOut, operationKind=1.
const publicAmountOut         = IS_WITHDRAW ? 8n : 0n;
const publicRecipientAddress  = IS_WITHDRAW
  ? 0x3333333333333333333333333333333333333333n
  : 0n;
const publicTokenAddress      = IS_WITHDRAW ? tokenAddress : 0n;
const operationKind           = IS_WITHDRAW ? 1n : 0n;
const intentAmount            = IS_WITHDRAW ? publicAmountOut : outAmount[0];

// ---- Blinded auth commitment + intent digest ----
const blindedAuthCommitment = poseidon(T.BLINDED_AUTH_COMMITMENT_DOMAIN, authDataCommitment, blindingFactor);
const transactionIntentDigest = poseidon(
  T.TRANSACTION_INTENT_DIGEST_DOMAIN,
  authVerifier,
  authorizingAddress,
  operationKind,
  tokenAddress,
  recipientOwnerNullifierKeyHash,
  intentAmount,
  feeNoteRecipientOwnerNullifierKeyHash,
  feeAmount,
  publicRecipientAddress,
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

const outName = MODE === 'transfer' ? 'pool_input.json' : `${MODE}_pool_input.json`;
const outPath = path.join(ROOT, 'build/integration_honk', outName);
fs.mkdirSync(path.dirname(outPath), { recursive: true });
fs.writeFileSync(outPath, JSON.stringify(out, null, 2));
console.log('mode:', MODE);
console.log('wrote', outPath);
console.log('  authorizingAddress       =', '0x' + authorizingAddress.toString(16).padStart(40, '0'));
console.log('  authVerifier             =', '0x' + authVerifier.toString(16).padStart(40, '0'));
console.log('  authDataCommitment       =', authDataCommitment.toString());
console.log('  blindedAuthCommitment    =', blindedAuthCommitment.toString());
console.log('  transactionIntentDigest  =', transactionIntentDigest.toString());
